# WebSocket Client Example - Secure Authentication

## ⚠️ SECURITY UPDATE

**BREAKING CHANGE:** WebSocket authentication telah diubah untuk keamanan yang lebih baik.

### ❌ OLD METHOD (INSECURE - DO NOT USE):
```javascript
// INSECURE: Token exposed di URL
const ws = new WebSocket('ws://localhost:8000/ws?token=eyJhbGc...');
```

**Masalah:**
- Token ter-expose di browser history
- Token ter-log di server logs
- Token ter-log di proxy logs
- Token dapat dicuri dari referrer headers

---

### ✅ NEW METHOD (SECURE):

```javascript
// 1. Connect tanpa token di URL
const ws = new WebSocket('ws://localhost:8000/ws');

// 2. Kirim auth message setelah connection
ws.onopen = () => {
    // Kirim authentication message
    ws.send(JSON.stringify({
        type: 'auth',
        token: 'your_jwt_token_here'
    }));
};

// 3. Handle auth response
ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    if (data.type === 'auth_success') {
        console.log('✅ Authenticated:', data.user_id);
        // Now you can send other messages
        ws.send('Hello, secure WebSocket!');
    } else if (data.error) {
        console.error('❌ Error:', data.error);
    } else {
        console.log('Message:', data);
    }
};

ws.onerror = (error) => {
    console.error('WebSocket error:', error);
};

ws.onclose = (event) => {
    console.log('WebSocket closed:', event.code, event.reason);
};
```

---

## Complete Example

```javascript
class SecureWebSocketClient {
    constructor(url, token) {
        this.url = url;
        this.token = token;
        this.ws = null;
        this.authenticated = false;
    }
    
    connect() {
        return new Promise((resolve, reject) => {
            this.ws = new WebSocket(this.url);
            
            this.ws.onopen = () => {
                console.log('WebSocket connected, authenticating...');
                
                // Send auth message
                this.ws.send(JSON.stringify({
                    type: 'auth',
                    token: this.token
                }));
                
                // Set timeout for authentication
                const authTimeout = setTimeout(() => {
                    if (!this.authenticated) {
                        reject(new Error('Authentication timeout'));
                        this.ws.close();
                    }
                }, 5000);
                
                // Handle auth response
                const authHandler = (event) => {
                    const data = JSON.parse(event.data);
                    
                    if (data.type === 'auth_success') {
                        clearTimeout(authTimeout);
                        this.authenticated = true;
                        console.log('✅ Authenticated as:', data.user_id);
                        this.ws.removeEventListener('message', authHandler);
                        resolve(this.ws);
                    } else if (data.error) {
                        clearTimeout(authTimeout);
                        reject(new Error(data.error));
                        this.ws.close();
                    }
                };
                
                this.ws.addEventListener('message', authHandler);
            };
            
            this.ws.onerror = (error) => {
                reject(error);
            };
            
            this.ws.onclose = (event) => {
                console.log('WebSocket closed:', event.code, event.reason);
                this.authenticated = false;
            };
        });
    }
    
    send(message) {
        if (!this.authenticated) {
            throw new Error('Not authenticated');
        }
        this.ws.send(message);
    }
    
    onMessage(callback) {
        this.ws.addEventListener('message', (event) => {
            const data = JSON.parse(event.data);
            if (data.type !== 'auth_success') {
                callback(data);
            }
        });
    }
    
    close() {
        if (this.ws) {
            this.ws.close();
        }
    }
}

// Usage
async function main() {
    try {
        const client = new SecureWebSocketClient(
            'ws://localhost:8000/ws',
            'your_jwt_token_here'
        );
        
        await client.connect();
        
        // Setup message handler
        client.onMessage((data) => {
            console.log('Received:', data);
        });
        
        // Send messages
        client.send('Hello, secure WebSocket!');
        client.send('This is a test message');
        
    } catch (error) {
        console.error('Failed to connect:', error);
    }
}

main();
```

---

## Python Client Example

```python
import asyncio
import websockets
import json

async def secure_websocket_client(url, token):
    async with websockets.connect(url) as websocket:
        # Send authentication message
        auth_msg = {
            "type": "auth",
            "token": token
        }
        await websocket.send(json.dumps(auth_msg))
        
        # Wait for auth response
        response = await websocket.recv()
        data = json.loads(response)
        
        if data.get("type") == "auth_success":
            print(f"✅ Authenticated as: {data['user_id']}")
            
            # Now you can send messages
            await websocket.send("Hello, secure WebSocket!")
            
            # Receive messages
            while True:
                message = await websocket.recv()
                print(f"Received: {message}")
        else:
            print(f"❌ Authentication failed: {data.get('error')}")

# Usage
asyncio.run(secure_websocket_client(
    "ws://localhost:8000/ws",
    "your_jwt_token_here"
))
```

---

## Error Handling

### Possible Errors:

1. **Authentication timeout** (5 seconds)
   ```json
   {"error": "Authentication timeout"}
   ```

2. **Invalid auth message format**
   ```json
   {
       "error": "First message must be authentication",
       "format": {"type": "auth", "token": "your_jwt_token"}
   }
   ```

3. **Token required**
   ```json
   {"error": "Token required"}
   ```

4. **Invalid or expired token**
   ```json
   {"error": "Invalid or expired token"}
   ```

5. **Rate limit exceeded**
   ```json
   {"error": "Rate limit exceeded"}
   ```

6. **Enhanced security not available**
   ```json
   {"error": "Enhanced security not available"}
   ```

---

## Security Benefits

✅ **Token tidak ter-expose di URL**  
✅ **Token tidak tersimpan di browser history**  
✅ **Token tidak ter-log di server logs**  
✅ **Token tidak ter-log di proxy logs**  
✅ **Token tidak ter-expose di referrer headers**  
✅ **5 second authentication timeout**  
✅ **Rate limiting protection**  
✅ **Input validation untuk semua messages**  

---

## Migration Guide

### Step 1: Update Client Code
Replace old WebSocket connection code with new secure method.

### Step 2: Test Authentication
Ensure authentication message is sent correctly.

### Step 3: Handle Errors
Implement proper error handling for auth failures.

### Step 4: Update Documentation
Update any client documentation or examples.

---

## FAQ

**Q: Kenapa tidak bisa kirim token di query parameter lagi?**  
A: Untuk keamanan. Token di URL ter-expose di banyak tempat (logs, history, etc).

**Q: Berapa timeout untuk authentication?**  
A: 5 detik. Client harus kirim auth message dalam 5 detik setelah connect.

**Q: Apa yang terjadi jika auth gagal?**  
A: WebSocket connection akan ditutup dengan error message yang jelas.

**Q: Apakah bisa reconnect otomatis?**  
A: Ya, client bisa implement reconnection logic dengan exponential backoff.

---

**Last Updated:** 2025-11-25  
**Security Level:** HIGH  
**Breaking Change:** YES
