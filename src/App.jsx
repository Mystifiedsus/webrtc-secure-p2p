import React, { useEffect, useRef, useState } from 'react';
import { auth, db, ensureSignedIn } from './firebase';
import { collection, addDoc, onSnapshot, doc, deleteDoc } from 'firebase/firestore';

const APP_ID = import.meta.env.VITE_APP_ID || 'default-app-id';
const initialAuthToken = window.__initial_auth_token || null;

export default function App() {
  const [userId, setUserId] = useState(null);
  const [peerIdInput, setPeerIdInput] = useState('');
  const [connectedPeerId, setConnectedPeerId] = useState('');
  const [connectionStatus, setConnectionStatus] = useState('disconnected');
  const [file, setFile] = useState(null);
  const [transferProgress, setTransferProgress] = useState(0);
  const [message, setMessage] = useState('Welcome! Generate/enter Peer ID to connect.');
  const [history, setHistory] = useState([]);
  const [receivedFile, setReceivedFile] = useState(null);
  const [isAuthReady, setIsAuthReady] = useState(false);

  const peerConnection = useRef(null);
  const dataChannel = useRef(null);
  const receiveBuffer = useRef([]);
  const receivedFileMetadata = useRef(null);
  const receivedSize = useRef(0);
  const symmetricKey = useRef(null);
  const cryptoKeyPair = useRef(null);

  useEffect(() => {
    (async () => {
      await ensureSignedIn(initialAuthToken);
      if (auth.currentUser) setUserId(auth.currentUser.uid);
      setIsAuthReady(true);
    })();
  }, []);

  useEffect(() => {
    if (!db || !userId || !isAuthReady) return;
    const signalingPath = `artifacts/${APP_ID}/users/${userId}/signaling`;
    const sigRef = collection(db, signalingPath);
    const unsub = onSnapshot(sigRef, async (snap) => {
      for (const change of snap.docChanges()) {
        if (change.type !== 'added') continue;
        const data = change.doc.data();
        if (data.senderId === userId) {
          await deleteDoc(doc(db, signalingPath, change.doc.id));
          continue;
        }
        try {
          if (data.type === 'offer') {
            await setupPeerConnection(data.senderId);
            const peerPublicKey = await crypto.subtle.importKey('jwk', data.publicKey, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
            const derivedBits = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerPublicKey }, cryptoKeyPair.current.privateKey, 256);
            symmetricKey.current = await crypto.subtle.importKey('raw', derivedBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt','decrypt']);
            await peerConnection.current.setRemoteDescription(data.offer);
            const answer = await peerConnection.current.createAnswer();
            await peerConnection.current.setLocalDescription(answer);
            const ownPublic = await crypto.subtle.exportKey('jwk', cryptoKeyPair.current.publicKey);
            await addDoc(collection(db, `artifacts/${APP_ID}/users/${data.senderId}/signaling`), { type:'answer', answer, publicKey: ownPublic, targetId: data.senderId, senderId: userId });
            setConnectedPeerId(data.senderId);
            setMessage('Received offer and sent answer.');
          } else if (data.type === 'answer' && data.targetId === userId) {
            const peerPublicKey = await crypto.subtle.importKey('jwk', data.publicKey, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
            const derivedBits = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerPublicKey }, cryptoKeyPair.current.privateKey, 256);
            symmetricKey.current = await crypto.subtle.importKey('raw', derivedBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt','decrypt']);
            await peerConnection.current.setRemoteDescription(data.answer);
            setMessage('Received answer and derived shared key.');
          } else if (data.type === 'candidate' && data.targetId === userId) {
            await peerConnection.current?.addIceCandidate(data.candidate);
          }
        } catch (e) {
          console.error('Signaling error', e);
          setMessage('Signaling error; see console.');
        } finally {
          await deleteDoc(doc(db, signalingPath, change.doc.id));
        }
      }
    });
    return () => unsub();
  }, [db, userId, isAuthReady]);

  useEffect(() => {
    if (!db || !userId || !isAuthReady) return;
    const histRef = collection(db, `artifacts/${APP_ID}/users/${userId}/fileHistory`);
    const unsub = onSnapshot(histRef, (snap) => {
      const recs = [];
      snap.forEach(d => recs.push(d.data()));
      recs.sort((a,b) => new Date(b.timestamp) - new Date(a.timestamp));
      setHistory(recs);
    });
    return () => unsub();
  }, [db, userId, isAuthReady]);

  async function setupPeerConnection(peerId) {
    cryptoKeyPair.current = await crypto.subtle.generateKey({ name:'ECDH', namedCurve:'P-256' }, true, ['deriveBits']);
    peerConnection.current = new RTCPeerConnection();
    peerConnection.current.onicecandidate = async (ev) => {
      if (ev.candidate) {
        try {
          await addDoc(collection(db, `artifacts/${APP_ID}/users/${peerId}/signaling`), { type:'candidate', candidate: ev.candidate.toJSON(), targetId: peerId, senderId: userId });
        } catch (e) { console.error('ICE send error', e); }
      }
    };
    peerConnection.current.ondatachannel = (ev) => { dataChannel.current = ev.channel; setupDataChannelEvents(); };
    peerConnection.current.onconnectionstatechange = () => setConnectionStatus(peerConnection.current.connectionState);

    dataChannel.current = peerConnection.current.createDataChannel('fileTransfer');
    setupDataChannelEvents();
  }

  function setupDataChannelEvents() {
    if (!dataChannel.current) return;
    dataChannel.current.onopen = () => { setConnectionStatus('connected'); setMessage('Connected.'); };
    dataChannel.current.onclose = () => { setConnectionStatus('disconnected'); setMessage('Disconnected.'); peerConnection.current = null; dataChannel.current = null; symmetricKey.current = null; };
    dataChannel.current.onmessage = async (ev) => {
      const msg = ev.data;
      if (typeof msg === 'string') {
        try {
          const parsed = JSON.parse(msg);
          if (parsed.type === 'fileMetadata') {
            receivedFileMetadata.current = parsed;
            receiveBuffer.current = [];
            receivedSize.current = 0;
            setMessage(`Receiving ${parsed.fileName}...`);
            setTransferProgress(0);
          }
        } catch (e) { }
      } else {
        try {
          if (!symmetricKey.current) throw new Error('No symmetric key');
          const buffer = msg;
          const iv = new Uint8Array(buffer.slice(0,12));
          const encrypted = buffer.slice(12);
          const decrypted = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, symmetricKey.current, encrypted);
          receiveBuffer.current.push(decrypted);
          receivedSize.current += decrypted.byteLength;
          const meta = receivedFileMetadata.current;
          if (meta?.fileSize) setTransferProgress((receivedSize.current / meta.fileSize) * 100);
          if (meta && receivedSize.current >= meta.fileSize) {
            const blob = new Blob(receiveBuffer.current, { type: meta.fileType });
            const fh = await hashFile(blob);
            if (fh === meta.fileHash) { setMessage('File received and verified'); setReceivedFile({ name: meta.fileName, blob }); }
            else { setMessage('File received but verification failed'); setReceivedFile(null); }
          }
        } catch (e) { console.error('decrypt', e); setMessage('Decrypt error'); }
      }
    };
  }

  function generatePeerId() { setPeerIdInput(Math.random().toString(36).slice(2,8)); setMessage('Peer ID generated'); }

  async function connectToPeer() {
    const peerId = (peerIdInput||'').trim();
    if (!peerId) { setMessage('Enter Peer ID'); return; }
    try {
      setMessage('Creating offer...'); setConnectionStatus('connecting');
      await setupPeerConnection(peerId);
      const publicKey = await crypto.subtle.exportKey('jwk', cryptoKeyPair.current.publicKey);
      const offer = await peerConnection.current.createOffer();
      await peerConnection.current.setLocalDescription(offer);
      await addDoc(collection(db, `artifacts/${APP_ID}/users/${peerId}/signaling`), { type:'offer', offer, publicKey, targetId: peerId, senderId: userId });
      setConnectedPeerId(peerId);
      setMessage('Offer sent');
    } catch (e) { console.error('connect', e); setMessage('Connection failed'); setConnectionStatus('disconnected'); }
  }

  function handleFileChange(e) { const f = e.target.files?.[0]; if (f) { setFile(f); setMessage(`Selected ${f.name}`); } }
  function handleDrop(e){ e.preventDefault(); const f = e.dataTransfer?.files?.[0]; if (f) { setFile(f); setMessage(`Selected ${f.name}`); } }
  function handleDragOver(e){ e.preventDefault(); }

  async function sendFile() {
    if (!file || !dataChannel.current || dataChannel.current.readyState!=='open') { setMessage('Select file and connect'); return; }
    if (!symmetricKey.current) { setMessage('No symmetric key'); return; }
    setMessage('Sending file...'); setTransferProgress(0);
    const reader = new FileReader();
    reader.onload = async (ev) => {
      const fileData = ev.target.result;
      const fileHash = await hashFile(new Blob([fileData]));
      await addDoc(collection(db, `artifacts/${APP_ID}/users/${userId}/fileHistory`), { senderId: userId, recipientId: connectedPeerId, fileName: file.name, fileHash, timestamp: new Date().toISOString() });
      dataChannel.current.send(JSON.stringify({ type:'fileMetadata', fileName: file.name, fileSize: file.size, fileType: file.type, fileHash }));
      const chunkSize = 16*1024;
      let offset = 0;
      while (offset < fileData.byteLength) {
        const chunk = fileData.slice(offset, offset + chunkSize);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, symmetricKey.current, chunk);
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);
        dataChannel.current.send(combined.buffer);
        offset += chunkSize;
        setTransferProgress((offset / fileData.byteLength) * 100);
      }
      setMessage('File sent');
    };
    reader.readAsArrayBuffer(file);
  }

  async function hashFile(blob) {
    const buf = await blob.arrayBuffer();
    const h = await crypto.subtle.digest('SHA-256', buf);
    const arr = Array.from(new Uint8Array(h));
    return arr.map(b => b.toString(16).padStart(2,'0')).join('');
  }

  function downloadFile() {
    if (!receivedFile) { setMessage('No file'); return; }
    const url = URL.createObjectURL(receivedFile.blob);
    const a = document.createElement('a');
    a.href = url; a.download = receivedFile.name; document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url); setReceivedFile(null); setMessage('Downloading');
  }

  return (
    <div className="container">
      <div className="card">
        <div className="h1">Secure P2P File Share</div>
        <div className="small">User ID: <span className="mono">{userId||'...'}</span></div>
        <div className="small">Connection: <strong>{connectionStatus}</strong></div>
      </div>

      <div className="card">
        <div className="small">Connect to a Peer</div>
        <div style={{display:'flex',gap:8}}>
          <input className="input" placeholder="Peer ID" value={peerIdInput} onChange={(e)=>setPeerIdInput(e.target.value)} />
          <button className="btn btn-primary" onClick={connectToPeer}>Connect</button>
          <button className="btn" onClick={generatePeerId}>Generate</button>
        </div>
      </div>

      <div className="card">
        <div className="small">File Transfer</div>
        <div className="box" onDragOver={handleDragOver} onDrop={handleDrop} onClick={()=>document.getElementById('file-input').click()}>
          <div style={{fontWeight:700}}>Drag & drop or click to choose</div>
          {file && <div className="small">Selected: {file.name}</div>}
          <input id="file-input" type="file" style={{display:'none'}} onChange={handleFileChange} />
        </div>
        <div style={{display:'flex',flexDirection:'column',gap:8,marginTop:8}}>
          <button className="btn btn-primary" onClick={sendFile} disabled={!file || connectionStatus!=='connected'}>Send File</button>
          <div className="progress"><div style={{width:`${transferProgress}%`}}></div></div>
          {receivedFile && <button className="btn" onClick={downloadFile}>Download {receivedFile.name}</button>}
        </div>
      </div>

      <div className="card small">
        <div style={{fontWeight:700}}>History</div>
        {history.length>0 ? history.map((r,i)=>(<div key={i} style={{marginTop:8}}><div>File: <strong>{r.fileName}</strong></div><div className="mono small">Hash: {r.fileHash}</div><div>To: {r.recipientId}</div></div>)) : <div>No history yet.</div>}
      </div>

      <div className="card badge" style={{textAlign:'center'}}>{message}</div>
    </div>
  );
}
