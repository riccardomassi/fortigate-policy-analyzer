# 🚀 GUIDA DETTAGLIATA DEPLOY SU RENDER.COM

Questa guida ti porta passo dopo passo nel deploy dell'applicazione FortiGate Policy Analyzer su Render.com.

---

## 📋 PREREQUISITI VERIFICATI

✅ Codice pronto per Render.com
✅ File `render.yaml` configurato
✅ Backend aggiornato con path relativi
✅ Frontend configurato per API URL variabile
✅ Dipendenze aggiornate (incluse Gunicorn)
✅ Commit e push su GitHub completati

---

## 🎯 STEP 1: ACCEDI A RENDER.COM

**Azione:**
1. Apri il browser: [dashboard.render.com](https://dashboard.render.com)
2. Clicca su **"Log In"** (in alto a destra)
3. Seleziona **"Continue with GitHub"**
4. Inserisci le tue credenziali GitHub
5. Autorizza Render.com a connettersi al tuo account

**Risultato atteso:** Vedi il Dashboard Render con eventuali servizi già esistenti

---

## 🎯 STEP 2: CONNETTI RENDER A GITHUB (se non già fatto)

**Azione:**
1. Nel Dashboard, clicca su **"New +"** (in alto a destra)
2. Seleziona **"Blueprint"**
3. Se appare una lista di repository, vai allo Step 3
4. Altrimenti clicca su  **"Configure account"**
5. Accanto a GitHub clicca **"Connect"**
6. Seleziona  **"riccardomassi/fortigate-policy-analyzer"**
7. Clicca **"Install"** / **"Authorize"**

**Risultato atteso:** Vedi la schermata per creare una nuova Blueprint

---

## 🎯 STEP 3: CREA LA BLUEPRINT (Importa dal Repository)

**Azione:**
1. Dopo aver connesso GitHub, dovresti vedere **"Connect a Repository"**
2. Clicca su **"Search for a repository"**
3. Seleziona **"riccardomassi/fortigate-policy-analyzer"**
4. **IMPORTANTE:** Nel campo **"Root Directory"** inserisci: `webapp`
   - Questo dice a Render che la configurazione è nella cartella webapp
5. Render rileverà automaticamente `render.yaml`

**Verifica:**
- Dovresti vedere due servizi elencati:
  - `fortinet-policy-analyzer-api` (Web Service)
  - `fortinet-policy-analyzer-web` (Static Site)

**Azione:**
6. Scorri verso il basso e clicca **"Approve and Deploy"**

**Risultato atteso:**
- Vedi entrambi i servizi in stato **"Deploy in progress"**
- I logs iniziano a scorrere

---

## 🎯 STEP 4: MONITORA IL DEPLOY (BACKEND - 5-7 min)

**Azione:**
1. Nel Dashboard, clicca su **"fortinet-policy-analyzer-api"**
2. Vai alla scheda **"Logs"** (di default dovresti essere già lì)
3. Osserva i log di build:
   ```
   ==> Clonando repository...
   ==> Building from render.yaml...
   ==> Running build command: pip install -r requirements.txt
   Collecting Flask>=2.3.3
   ...
   ==> Running start command: gunicorn backend.app:app
   ```

**Aspetta 5-7 minuti** finché non vedi:
```
Server running on http://0.0.0.0:8515
```

**Segno di successo:**
- In alto: **Status: Live**
- Health Check: **Success**
- Response Time: < 1s

**NOTA:** L'URL del backend apparirà qui. **Copialo** (es: `https://fortinet-policy-analyzer-api-abc123.onrender.com`)

---

## 🎯 STEP 5: MONITORA IL DEPLOY (FRONTEND - 2-3 min)

**Azione:**
1. Torna al Dashboard
2. Clicca su **"fortinet-policy-analyzer-web"**
3. Vai alla scheda **"Logs"**
4. Osserva i log di build:
   ```
   ==> Clonando repository...
   ==> Building from render.yaml...
   ==> Running build command: cd frontend && npm install && npm run build
   ...
   Vite build complete
   ==> Uploading static files to CDN...
   ```

**Aspetta 2-3 minuti** finché non vedi:
```
Static site deployed successfully
```

**Segno di successo:**
- In alto: **Status: Live**
- URL: **https://fortinet-policy-analyzer-web-xyz789.onrender.com**

**Copia l'URL del frontend** (lo utilizzerai per testare)

---

## 🎯 STEP 6: CONFIGURA VITE_API_URL (CRITICO!)

Questo è lo step più importante. Il frontend deve sapere dove trovare il backend.

**Azione:**
1. Vai di nuovo a **"fortinet-policy-analyzer-web"** (clicca sopra)
2. Clicca sulla scheda **"Settings"**
3. Scorri fino a **"Environment"**
4. Trova la variabile **VITE_API_URL**
5. Clicca sulla matita (✏️) per modificarla
6. Sostituisci:
   ```
   # DA:
   https://YOUR_BACKEND_URL.onrender.com

   # A (esempio):
   https://fortinet-policy-analyzer-api-abc123.onrender.com
   ```
   **Nota:** L'URL deve includere `https://` ma **NON** mettere `/` alla fine

7. Clicca **"Save"**

**Risultato atteso:**
- La variabile è ora aggiornata
- A destra vedi: **Service will be rebuilt**

**Azione:**
8. Clicca **"Yes, deploy latest commit"**

Il frontend si ricostruirà con il corretto URL del backend (1-2 min).

---

## 🎯 STEP 7: TEST L'APPLICAZIONE

**Azione:**
1. Torna al Dashboard Render
2. Clicca su **"fortinet-policy-analyzer-web"**
3. In alto troverai l'URL (es: `https://fortinet-policy-analyzer-web-xyz789.onrender.com`)
4. **Copia e apri nel browser**

**Test:**
1. Dovresti vedere l'interfaccia del FortiGate Policy Analyzer
2. Prova a trascinare un file `.conf` nell'area upload
3. Se tutto è corretto, il file si caricherà e potrai analizzarlo

**Segno di successo:**
- ✅ File caricato con successo
- ✅ Analisi completata
- ✅ Risultati visualizzati correttamente

---

## 🎯 STEP 8: VERIFICA CONFIGURAZIONE

**Test importanti da fare:**

### Test 1: Health Check Backend
Apri il browser e vai a:
```
https://YOUR_BACKEND_URL.onrender.com/api/health
```
Dovresti vedere:
```json
{"status": "healthy", "timestamp": "2024-03-19T13:45:00", "version": "1.0.0"}
```

### Test 2: Upload File
Usa un file `.conf` di test (massimo 50MB) per verificare l'intero workflow:
1. Carica file
2. Configura analisi
3. Avvia analisi
4. Controlla risultati

---

## 🔍 TROUBLESHOOTING GUIDE

### Problema 1: "Backend connection failed" nel frontend
**Soluzione:**
- Verifica che `VITE_API_URL` nel frontend contenga l'URL corretto del backend
- Assicurati di aver incluso `https://` all'inizio
- Controlla che il backend sia in stato **Live**
- Nel frontend Settings → Environment → Ricontrolla VITE_API_URL

**Debug:**
```bash
curl https://YOUR_BACKEND_URL.onrender.com/api/health
```

### Problema 2: "Deploy failed" nel backend
**Causa comune:** File `fortigate_policy_analyzer.py` non trovato

**Soluzione:**
- Verifica che `fortigate_policy_analyzer.py` sia nella **root del repository** (stessa cartella di `webapp/`, non dentro)
- Struttura corretta:
  ```
  /
  ├── fortigate_policy_analyzer.py
  ├── webapp/
  │   ├── backend/
  │   ├── frontend/
  │   └── render.yaml
  ```

### Problema 3: "Module not found" nel build
**Causa:** requirements.txt non completo

**Soluzione:**
- Verifica che `webapp/requirements.txt` contenga:
  ```
  Flask>=2.3.3
  Flask-CORS>=4.0.0
  Werkzeug>=2.3.7
  Gunicorn>=21.0.0
  ```

### Problema 4: "File not found" durante analisi
**Causa:** Disk non correttamente montato

**Soluzione:**
- Nel backend Settings → Disk → Verifica che sia presente
- Nome: `uploads`
- Mount Path: `/opt/render/project/src/uploads`

### Problema 5: 404 Not Found su `/api/*`
**Causa:** `render.yaml` non specifica `Root Directory: webapp`

**Soluzione:**
- Ricreare blueprint specificando `Root Directory: webapp`
- Oppure spostare `render.yaml` nella root del repository

### Problema 6: Frontend build fallisce
**Causa:** Node.js versione errata

**Soluzione:**
- Nel frontend Settings → Environment → Aggiungi:
  ```
  Key: NODE_VERSION
  Value: 18
  ```
- Ricostruisci il servizio

---

## 📊 STATUS SEGNI DI SUCCESSO

### Green Flags ✅
- Backend Status: **Live**
- Frontend Status: **Live**
- Health Check: **200 OK**
- File upload: **Success**
- Analisi: **Completa**

### Red Flags ❌
- Backend: **Deploy Failed**
- Frontend: **Failed to fetch /api**
- Logs: **ModuleNotFoundError**
- Logs: **FileNotFoundError: fortigate_policy_analyzer.py**

---

## 📝 CHECKLIST FINALE

- [ ] Step 1: Acceso a Render.com ✅
- [ ] Step 2: GitHub connesso ✅
- [ ] Step 3: Blueprint creata ✅
- [ ] Step 4: Backend deployato (Live) ✅
- [ ] Step 5: Frontend deployato (Live) ✅
- [ ] Step 6: VITE_API_URL aggiornato ✅
- [ ] Step 7: Frontend ricostruito ✅
- [ ] Step 8: Applicazione testata ✅
- [ ] File upload funziona ✅
- [ ] Analisi completa ✅

**Se tutti i check sono ✅, congratulazioni! 🎉**

---

## 📞 SUPPORTO

Se incontri problemi:
1. **Fai uno screenshot dell'errore**
2. **Copia i logs rilevanti**
3. **Segnami lo step in cui sei bloccato**

Inviemi queste informazioni e ti aiuterò a risolvere il problema!

**Nota:** Non modificare il file durante il deploy. Attendi che tutto sia completato prima di fare cambiamenti.

---

## 💡 CONSIGLI PER IL FUTURO

### Aggiornamenti Automatici
Render.com rileverà automaticamente:
- ✅ Push su GitHub → Trigger rebuild automatico (se abilitato)
- ✅ Modifiche a `render.yaml` → Ricreazione servizi
- ✅ Modifiche a `requirements.txt` → Rebuild necessario

### Monitoraggio
- Abilita **Email Notifications** in Settings → Notifications
- Aggiungi **PagerDuty** o **Slack** per alert in produzione

### Custom Domains
1. Acquista dominio (es: namecheap.com, porkbun.com)
2. In backend Settings → Custom Domains → Add custom domain
3. In frontend Settings → Custom Domains → Add custom domain
4. Configura DNS (CNAME o ANAME)
5. Aggiorna VITE_API_URL con nuovo dominio

### Database Persistent (se necessario in futuro)
Render.com offre PostgreSQL managed per dati persistenti

---

**Buon deploy! 🚀**
