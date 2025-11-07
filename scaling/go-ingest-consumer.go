package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/Shopify/sarama"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ThreatLog struct {
	Timestamp time.Time `bson:"timestamp"`
	Meta      struct {
		SourceID   string `bson:"source_id"`
		SourceIP   string `bson:"source_ip"`
		AttackType string `bson:"attack_type"`
		Severity   string `bson:"severity"`
		ShardKey   int    `bson:"shard_key"`
	} `bson:"meta"`
	Fields struct {
		Raw        interface{} `bson:"raw"`
		Score      float64     `bson:"score"`
		AgentVotes interface{} `bson:"agent_votes"`
	} `bson:"fields"`
}

type BulkConsumer struct {
	client     *mongo.Client
	collection *mongo.Collection
	consumer   sarama.ConsumerGroup
	batchSize  int
	batch      []interface{}
}

func NewBulkConsumer(mongoURI string, kafkaBrokers []string, topic string) (*BulkConsumer, error) {
	// MongoDB connection
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI).SetMaxPoolSize(200))
	if err != nil {
		return nil, err
	}

	collection := client.Database("infinite_security").Collection("threat_logs")

	// Kafka consumer
	config := sarama.NewConfig()
	config.Consumer.Group.Rebalance.Strategy = sarama.BalanceStrategyRoundRobin
	config.Consumer.Offsets.Initial = sarama.OffsetNewest
	config.Consumer.Group.Session.Timeout = 10 * time.Second
	config.Consumer.Group.Heartbeat.Interval = 3 * time.Second

	consumer, err := sarama.NewConsumerGroup(kafkaBrokers, "go-ingest-workers", config)
	if err != nil {
		return nil, err
	}

	return &BulkConsumer{
		client:     client,
		collection: collection,
		consumer:   consumer,
		batchSize:  1000,
		batch:      make([]interface{}, 0, 1000),
	}, nil
}

func (bc *BulkConsumer) insertBatch(ctx context.Context) error {
	if len(bc.batch) == 0 {
		return nil
	}

	opts := options.InsertMany().SetOrdered(false)
	_, err := bc.collection.InsertMany(ctx, bc.batch, opts)
	if err != nil {
		log.Printf("Insert error: %v", err)
		return err
	}

	log.Printf("Inserted %d documents", len(bc.batch))
	bc.batch = bc.batch[:0] // Reset batch
	return nil
}

func (bc *BulkConsumer) Setup(sarama.ConsumerGroupSession) error   { return nil }
func (bc *BulkConsumer) Cleanup(sarama.ConsumerGroupSession) error { return nil }

func (bc *BulkConsumer) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	ctx := context.Background()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case message := <-claim.Messages():
			if message == nil {
				return nil
			}

			var rawLog map[string]interface{}
			if err := json.Unmarshal(message.Value, &rawLog); err != nil {
				log.Printf("JSON unmarshal error: %v", err)
				continue
			}

			// Transform to time-series format
			threatLog := ThreatLog{
				Timestamp: time.Now(),
			}

			if ts, ok := rawLog["timestamp"].(string); ok {
				if parsed, err := time.Parse(time.RFC3339, ts); err == nil {
					threatLog.Timestamp = parsed
				}
			}

			threatLog.Meta.SourceID = getStringField(rawLog, "source_id", "unknown")
			threatLog.Meta.SourceIP = getStringField(rawLog, "source_ip", "0.0.0.0")
			threatLog.Meta.AttackType = getStringField(rawLog, "attack_type", "unknown")
			threatLog.Meta.Severity = getStringField(rawLog, "severity", "low")
			threatLog.Meta.ShardKey = hash(threatLog.Meta.SourceID) % 1000

			threatLog.Fields.Raw = rawLog["raw"]
			threatLog.Fields.Score = getFloatField(rawLog, "score", 0.0)
			threatLog.Fields.AgentVotes = rawLog["agent_votes"]

			bc.batch = append(bc.batch, threatLog)

			if len(bc.batch) >= bc.batchSize {
				if err := bc.insertBatch(ctx); err != nil {
					log.Printf("Batch insert failed: %v", err)
				}
			}

			session.MarkMessage(message, "")

		case <-ticker.C:
			if len(bc.batch) > 0 {
				if err := bc.insertBatch(ctx); err != nil {
					log.Printf("Periodic flush failed: %v", err)
				}
			}
		}
	}
}

func getStringField(m map[string]interface{}, key, defaultVal string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return defaultVal
}

func getFloatField(m map[string]interface{}, key string, defaultVal float64) float64 {
	if val, ok := m[key].(float64); ok {
		return val
	}
	return defaultVal
}

func hash(s string) int {
	h := 0
	for _, c := range s {
		h = 31*h + int(c)
	}
	if h < 0 {
		h = -h
	}
	return h
}

func main() {
	consumer, err := NewBulkConsumer(
		"mongodb://mongos:27017",
		[]string{"kafka1:29092", "kafka2:29092", "kafka3:29092"},
		"threat-logs",
	)
	if err != nil {
		log.Fatal("Failed to create consumer:", err)
	}

	ctx := context.Background()
	for {
		if err := consumer.consumer.Consume(ctx, []string{"threat-logs"}, consumer); err != nil {
			log.Printf("Error from consumer: %v", err)
		}
		if ctx.Err() != nil {
			return
		}
	}
}