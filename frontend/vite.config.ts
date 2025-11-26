import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [react()],
    server: {
        port: 3000,
        proxy: {
            // Proxy API requests to the API‑Gateway running on host port 8030
            '/api': {
                target: 'http://localhost:8030',
                changeOrigin: true,
                secure: false,
            },
        },
    },
})
