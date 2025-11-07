#include <iostream>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>

#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>

#include <librdkafka/rdkafkacpp.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace std::chrono;

class BulkIngestConsumer : public RdKafka::RebalanceCb, public RdKafka::EventCb {
private:
    mongocxx::client mongo_client;
    mongocxx::collection collection;
    std::unique_ptr<RdKafka::KafkaConsumer> consumer;
    
    std::vector<bsoncxx::document::value> batch;
    std::mutex batch_mutex;
    std::condition_variable batch_cv;
    
    const size_t batch_size = 1000;
    const int flush_interval_ms = 500;
    std::atomic<bool> running{true};

public:
    BulkIngestConsumer(const std::string& mongo_uri, const std::string& kafka_brokers, const std::string& topic) 
        : mongo_client(mongocxx::uri{mongo_uri}),
          collection(mongo_client["infinite_security"]["threat_logs"]) {
        
        // Kafka configuration
        std::string errstr;
        RdKafka::Conf* conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
        
        conf->set("metadata.broker.list", kafka_brokers, errstr);
        conf->set("group.id", "cpp-ingest-workers", errstr);
        conf->set("enable.auto.commit", "true", errstr);
        conf->set("auto.offset.reset", "latest", errstr);
        conf->set("rebalance_cb", this, errstr);
        conf->set("event_cb", this, errstr);
        
        consumer.reset(RdKafka::KafkaConsumer::create(conf, errstr));
        if (!consumer) {
            throw std::runtime_error("Failed to create consumer: " + errstr);
        }
        
        std::vector<std::string> topics = {topic};
        RdKafka::ErrorCode err = consumer->subscribe(topics);
        if (err) {
            throw std::runtime_error("Failed to subscribe: " + RdKafka::err2str(err));
        }
        
        delete conf;
        batch.reserve(batch_size);
    }
    
    void rebalance_cb(RdKafka::KafkaConsumer* consumer,
                     RdKafka::ErrorCode err,
                     std::vector<RdKafka::TopicPartition*>& partitions) override {
        if (err == RdKafka::ERR__ASSIGN_PARTITIONS) {
            consumer->assign(partitions);
        } else {
            consumer->unassign();
        }
    }
    
    void event_cb(RdKafka::Event& event) override {
        if (event.type() == RdKafka::Event::EVENT_ERROR) {
            std::cerr << "Kafka error: " << event.str() << std::endl;
        }
    }
    
    bsoncxx::document::value transform_message(const std::string& payload) {
        auto json_doc = json::parse(payload);
        
        using bsoncxx::builder::stream::document;
        using bsoncxx::builder::stream::open_document;
        using bsoncxx::builder::stream::close_document;
        using bsoncxx::builder::stream::finalize;
        
        auto now = system_clock::now();
        auto timestamp = bsoncxx::types::b_date{now};
        
        // Parse timestamp if provided
        if (json_doc.contains("timestamp")) {
            // Simplified timestamp parsing
            timestamp = bsoncxx::types::b_date{now};
        }
        
        std::string source_id = json_doc.value("source_id", "unknown");
        std::hash<std::string> hasher;
        size_t shard_key = hasher(source_id) % 1000;
        
        return document{}
            << "timestamp" << timestamp
            << "meta" << open_document
                << "source_id" << json_doc.value("source_id", "unknown")
                << "source_ip" << json_doc.value("source_ip", "0.0.0.0")
                << "attack_type" << json_doc.value("attack_type", "unknown")
                << "severity" << json_doc.value("severity", "low")
                << "shard_key" << static_cast<int32_t>(shard_key)
            << close_document
            << "fields" << open_document
                << "raw" << bsoncxx::from_json(json_doc.value("raw", json::object()).dump())
                << "score" << json_doc.value("score", 0.0)
                << "agent_votes" << bsoncxx::from_json(json_doc.value("agent_votes", json::object()).dump())
            << close_document
            << finalize;
    }
    
    void insert_batch() {
        std::lock_guard<std::mutex> lock(batch_mutex);
        if (batch.empty()) return;
        
        try {
            mongocxx::options::insert insert_opts;
            insert_opts.ordered(false);
            
            auto result = collection.insert_many(batch, insert_opts);
            std::cout << "Inserted " << batch.size() << " documents" << std::endl;
            
            batch.clear();
        } catch (const std::exception& e) {
            std::cerr << "Insert error: " << e.what() << std::endl;
        }
    }
    
    void flush_worker() {
        while (running) {
            std::this_thread::sleep_for(milliseconds(flush_interval_ms));
            
            std::unique_lock<std::mutex> lock(batch_mutex);
            if (!batch.empty()) {
                lock.unlock();
                insert_batch();
            }
        }
    }
    
    void consume_loop() {
        std::thread flush_thread(&BulkIngestConsumer::flush_worker, this);
        
        while (running) {
            std::unique_ptr<RdKafka::Message> msg(consumer->consume(1000));
            
            switch (msg->err()) {
                case RdKafka::ERR_NO_ERROR: {
                    std::string payload(static_cast<const char*>(msg->payload()), msg->len());
                    
                    try {
                        auto doc = transform_message(payload);
                        
                        std::lock_guard<std::mutex> lock(batch_mutex);
                        batch.push_back(std::move(doc));
                        
                        if (batch.size() >= batch_size) {
                            batch_cv.notify_one();
                            // Insert immediately for full batch
                            auto batch_copy = std::move(batch);
                            batch.clear();
                            batch.reserve(batch_size);
                            
                            // Insert without holding lock
                            try {
                                mongocxx::options::insert insert_opts;
                                insert_opts.ordered(false);
                                auto result = collection.insert_many(batch_copy, insert_opts);
                                std::cout << "Inserted " << batch_copy.size() << " documents" << std::endl;
                            } catch (const std::exception& e) {
                                std::cerr << "Batch insert error: " << e.what() << std::endl;
                            }
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "Transform error: " << e.what() << std::endl;
                    }
                    break;
                }
                case RdKafka::ERR__TIMED_OUT:
                    break;
                default:
                    std::cerr << "Consume error: " << msg->errstr() << std::endl;
                    break;
            }
        }
        
        flush_thread.join();
    }
    
    void stop() {
        running = false;
        consumer->close();
    }
};

int main() {
    mongocxx::instance instance{};
    
    try {
        BulkIngestConsumer consumer(
            "mongodb://mongos:27017",
            "kafka1:29092,kafka2:29092,kafka3:29092",
            "threat-logs"
        );
        
        std::cout << "Starting C++ bulk ingest consumer..." << std::endl;
        consumer.consume_loop();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}