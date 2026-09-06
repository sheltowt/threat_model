import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App.js';
import './styles.css';

const host = document.getElementById('root');
if (!host) throw new Error('tmc: #root is missing from index.html');

createRoot(host).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
