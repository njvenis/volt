import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './tokens.css';
import './styles.css';
import './v2-workspace.css';
createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
