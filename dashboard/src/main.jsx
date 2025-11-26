import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './utils/console.js'

// Disable all console output
console.log = () => {};
console.warn = () => {};
console.error = () => {};
console.info = () => {};
console.debug = () => {};

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)