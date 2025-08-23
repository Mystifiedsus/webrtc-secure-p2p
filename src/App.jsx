import React, { useEffect, useRef, useState } from 'react';
import { auth, db, ensureSignedIn } from './firebase';
import {
  addDoc, collection, deleteDoc, doc, onSnapshot, query
} from 'firebase/firestore';

const APP_ID = import.meta.env.VITE_APP_ID || 'default-app-id';
const initialAuthToken = window.__initial_auth_token || null;

export default function App() {
  const [userId, setUserId] = useState(null);
  const [peerIdInput, setPeerIdInput] = useState('');
  const [connectedPeerId, setConnectedPeerId] = useState('');
  const [connectionStatus, setConnectionStatus] = useState('disconnected');
  const [file, setFile] = useState(null);
  const [transferProgress, setTransferProgress] = useState(0);
  const [message, setMessage] = useState('Welcome! Generate an ID or enter one to connect.');
  const [isAuthReady, setIsAuthReady] = useState(false);
  const [history, setHistory] = useState([]);
  const [receivedFile, setReceivedFile] = useState(null);

  // WebRTC / Crypto refs
  const peerConnection = useRef(null);
  const dataChannel = useRef(null);
  const receiveBuffer = useRef([]);
  const receivedFileMetadata = useRef(null);
  const receivedSize = useRef(0);
  const symmetricKey = useRef(null);
  const cryptoKeyPair = useRef(null);

  // --- Auth init ---
  useEffect(() => {
    (async () => {
      await ensureSignedIn(initialAuthToken);
      if (auth.currentUser) setUserId(auth.currentUser.uid);
      setIsAuthReady(true);
    })().catch((e) => {
      console.error('Firebase initialization failed:', e);
      setMessage('Error initializing Firebase. Check your Firebase config/env.');
    });
  }, []);

  // --- Signaling listener ---
  useEffect(() => {
    if (!db || !userId || !isAuthReady) return;
    const signalingCollectionPath = `artifacts/${APP_ID}/users/${userId}/signaling`;
    const signalingCollectionRef = collection(db, signalingCollectionPath);
    const qSig = query(signalingCollectionRef);

    const unsub = onSnapshot(qSig, async (snap) => {
      for (const change of snap.docChanges()) {
        if (change.type !== 'added') continue;
        const data = change.doc.data();
        if (data.senderId === userId) {
          await deleteDoc(doc(db, signalingCollectionPath, change.doc.id));
          continue;
        }
        try {
          if (data.type === 'offer') {
            // Prepare connection as answerer
            await setupPeerConnection(data.senderId);
            // Derive shared key using their public key
            const peerPublicKey = await crypto.subtle.importKey(
              'jwk', data.publicKey, { name: 'ECDH', namedCurve: 'P-256' }, false, []
            );
            const derivedBits = await crypto.subtle.deriveBits(
              { name: 'ECDH', public: peerPublicKey },
              cryptoKeyPair.current.privateKey,
              256
            );
            symmetricKey.current = await crypto.subtle.importKey(
              'raw', derivedBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
            );
            await peerConnection.current.setRemoteDescription(data.offer);
            const answer = await peerConnection.current.createAnswer();
            await peerConnection.current.setLocalDescription(answer);
            const ownPublicKey = await crypto.subtle.exportKey('jwk', cryptoKeyPair.current.publicKey);

            await addDoc(collection(db, `artifacts/${APP_ID}/users/${data.senderId}/signaling`), {
              type: 'answer',
              answer,
              publicKey: ownPublicKey,
              targetId: data.senderId,
              senderId: userId
            });
            setConnectedPeerId(data.senderId);
            setMessage('Received offer, created answer and derived shared key.');
          } else if (data.type === 'answer' && data.targetId === userId) {
            // Initiator receives answer and derives key
            const peerPublicKey = await crypto.subtle.importKey(
              'jwk', data.publicKey, { name: 'ECDH', namedCurve: 'P-256' }, false, []
            );
            const derivedBits = await crypto.subtle.deriveBits(
              { name: 'ECDH', public: peerPublicKey },
              cryptoKeyPair.current.privateKey,
              256
            );
            symmetricKey.current = await crypto.subtle.importKey(
              'raw', derivedBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
            );
            await peerConnection.current.setRemoteDescription(data.answer);
            setMessage('Received answer, connection established and shared key derived.');
          } else if (data.type === 'candidate' && data.targetId === userId) {
            await peerConnection.current?.addIceCandidate(data.candidate);
          }
        } catch (e) {
          console.error('Error handling signaling message:', e);
          setMessage('Failed to process signaling message. See console.');
        } finally {
          await deleteDoc(doc(db, signalingCollectionPath, change.doc.id));
        }
      }
    });

    return () => unsub();
  }, [db, userId, isAuthReady]);

  // --- History listener ---
  useEffect(() => {
    if (!db || !userId || !isAuthReady) return;
    const historyCollectionRef = collection(db, `artifacts/${APP_ID}/users/${userId}/fileHistory`);
    const unsub = onSnapshot(historyCollectionRef, (snap) => {
      const records = [];
      snap.forEach((d) => records.push(d.data()));
      records.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      setHistory(records);
    });
    return () => unsub();
  }, [db, userId, isAuthReady]);

  async function setupPeerConnection(peerId) {
    // Generate ECDH keys
    cryptoKeyPair.current = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );
    peerConnection.current = new RTCPeerConnection();
    peerConnection.current.onicecandidate = async (event) => {
      if (event.candidate) {
        try {
          await addDoc(collection(db, `artifacts/${APP_ID}/users/${peerId}/signaling`), {
            type: 'candidate',
            candidate: event.candidate.toJSON(),
            targetId: peerId,
            senderId: userId
          });
        } catch (e) {
          console.error('Error sending ICE candidate:', e);
        }
      }
    };
    peerConnection.current.ondatachannel = (event) => {
      dataChannel.current = event.channel;
      setupDataChannelEvents();
    };
    peerConnection.current.onconnectionstatechange = () => {
      setConnectionStatus(peerConnection.current.connectionState);
    };
    // Create channel if we're the caller
    dataChannel.current = peerConnection.current.createDataChannel('fileTransfer');
    setupDataChannelEvents();
  }

  function setupDataChannelEvents() {
    if (!dataChannel.current) return;
    dataChannel.current.onopen = () => {
      setConnectionStatus('connected');
      setMessage('Connection established. You can now send or receive files.');
    };
    dataChannel.current.onclose = () => {
      setConnectionStatus('disconnected');
      setMessage('Peer disconnected. Click "Connect" to re-establish.');
      peerConnection.current = null;
      dataChannel.current = null;
      symmetricKey.current = null;
    };
    dataChannel.current.onmessage = async (event) => {
      const msg = event.data;
      if (typeof msg === 'string') {
        try {
          const parsed = JSON.parse(msg);
          if (parsed.type === 'fileMetadata') {
            receivedFileMetadata.current = parsed;
            receiveBuffer.current = [];
            receivedSize.current = 0;
            setMessage(`Receiving file: ${parsed.fileName} (${(parsed.fileSize / 1024 / 1024).toFixed(2)} MB)...`);
            setTransferProgress(0);
          }
        } catch (e) {
          // Not JSON
        }
      } else {
        try {
          if (!symmetricKey.current) throw new Error('Symmetric key not established.');
          const buffer = msg;
          const iv = new Uint8Array(buffer.slice(0, 12));
          const encryptedData = buffer.slice(12);
          const decryptedChunk = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            symmetricKey.current,
            encryptedData
          );
          receiveBuffer.current.push(decryptedChunk);
          receivedSize.current += decryptedChunk.byteLength;
          const meta = receivedFileMetadata.current;
          if (meta?.fileSize) {
            setTransferProgress((receivedSize.current / meta.fileSize) * 100);
          }
          if (meta && receivedSize.current >= meta.fileSize) {
            const receivedBlob = new Blob(receiveBuffer.current, { type: meta.fileType });
            const receivedFileHash = await hashFile(receivedBlob);
            if (receivedFileHash === meta.fileHash) {
              setMessage('File received and verified successfully!');
              setReceivedFile({ name: meta.fileName, blob: receivedBlob });
            } else {
              setMessage('File transfer complete, but verification failed.');
              setReceivedFile(null);
            }
          }
        } catch (e) {
          console.error('Error decrypting file chunk:', e);
          setMessage('Error decrypting file. Transfer failed.');
        }
      }
    };
  }

  function generatePeerId() {
    const id = Math.random().toString(36).slice(2, 8);
    setPeerIdInput(id);
    setMessage(`Your Peer ID is: ${id}. Share this with your partner.`);
  }

  async function connectToPeer() {
    const peerId = (peerIdInput || '').trim();
    if (!peerId || !db || !userId) {
      setMessage('Please enter a valid Peer ID first.');
      return;
    }
    try {
      setMessage('Creating connection offer...');
      setConnectionStatus('connecting');
      await setupPeerConnection(peerId);

      const publicKey = await crypto.subtle.exportKey('jwk', cryptoKeyPair.current.publicKey);
      const offer = await peerConnection.current.createOffer();
      await peerConnection.current.setLocalDescription(offer);

      await addDoc(collection(db, `artifacts/${APP_ID}/users/${peerId}/signaling`), {
        type: 'offer',
        offer,
        publicKey,
        targetId: peerId,
        senderId: userId
      });
      setConnectedPeerId(peerId);
      setMessage('Offer sent. Waiting for peer to accept...');
    } catch (e) {
      console.error('Connection failed:', e);
      setMessage('Failed to connect to peer. Check the ID and try again.');
      setConnectionStatus('disconnected');
    }
  }

  function handleFileChange(e) {
    const f = e.target.files?.[0] || null;
    if (f) {
      setFile(f);
      setMessage(`File selected: ${f.name}`);
    }
  }

  function handleDragOver(e) { e.preventDefault(); }
  function handleDrop(e) {
    e.preventDefault();
    const f = e.dataTransfer.files?.[0] || null;
    if (f) {
      setFile(f);
      setMessage(`File selected: ${f.name}`);
    }
  }

  async function sendFile() {
    if (!file || !dataChannel.current || dataChannel.current.readyState !== 'open') {
      setMessage('Please select a file and ensure you are connected to a peer.'); return;
    }
    if (!symmetricKey.current) { setMessage('Error: Symmetric key not established.'); return; }

    setMessage('Encrypting and sending file...');
    setTransferProgress(0);

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const fileData = e.target.result;
        const fileHash = await hashFile(new Blob([fileData]));

        const transferRecord = {
          senderId: userId,
          recipientId: connectedPeerId,
          fileName: file.name,
          fileHash,
          timestamp: new Date().toISOString(),
        };
        await addDoc(collection(db, `artifacts/${APP_ID}/users/${userId}/fileHistory`), transferRecord);

        dataChannel.current.send(JSON.stringify({
          type: 'fileMetadata',
          fileName: file.name,
          fileSize: file.size,
          fileType: file.type,
          fileHash
        }));

        const chunkSize = 16 * 1024;
        let offset = 0;
        while (offset < fileData.byteLength) {
          const chunk = fileData.slice(offset, offset + chunkSize);
          const iv = crypto.getRandomValues(new Uint8Array(12));
          const encryptedChunk = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            symmetricKey.current,
            chunk
          );
          const combined = new Uint8Array(iv.length + encryptedChunk.byteLength);
          combined.set(iv, 0);
          combined.set(new Uint8Array(encryptedChunk), iv.length);
          dataChannel.current.send(combined.buffer);
          offset += chunkSize;
          setTransferProgress((offset / fileData.byteLength) * 100);
        }
        setMessage('File sent successfully!');
      } catch (err) {
        console.error('File transfer failed:', err);
        setMessage('Error during file transfer. Check connection and try again.');
      }
    };
    reader.readAsArrayBuffer(file);
  }

  async function hashFile(blob) {
    const buf = await blob.arrayBuffer();
    const hash = await crypto.subtle.digest('SHA-256', buf);
    const bytes = Array.from(new Uint8Array(hash));
    return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function downloadFile() {
    if (!receivedFile) { setMessage('No file to download.'); return; }
    const url = URL.createObjectURL(receivedFile.blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = receivedFile.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setMessage(`Downloading ${receivedFile.name}...`);
    setReceivedFile(null);
  }

  return (
    <div className="container">
      <div className="card">
        <div className="h1">Secure P2P File Share</div>
        <div className="small">Current User ID: <span className="mono">{userId || '...'}</span></div>
        <div className="small">Connection status: <strong>{connectionStatus}</strong></div>
      </div>

      <div className="card">
        <div className="h2">Connect to a Peer</div>
        <div className="flex" style={{flexWrap:'wrap'}}>
          <input
            className="input" placeholder="Enter Peer ID" value={peerIdInput}
            onChange={(e) => setPeerIdInput(e.target.value)} style={{flex:1, minWidth:'200px'}}
          />
          <button className="btn btn-primary" onClick={connectToPeer}>Connect</button>
          <button className="btn btn-secondary" onClick={generatePeerId}>Generate New ID</button>
        </div>
      </div>

      <div className="card">
        <div className="h2">File Transfer</div>
        <div
          className="box"
          onDragOver={handleDragOver}
          onDrop={handleDrop}
          onClick={() => document.getElementById('file-input').click()}
        >
          <div style={{fontWeight:700}}>Drag & drop a file here, or click to browse</div>
          {file && <div className="small">Selected: {file.name}</div>}
          <input id="file-input" type="file" style={{display:'none'}} onChange={handleFileChange} />
        </div>
        <div className="flex-col">
          <button className="btn btn-success" onClick={sendFile} disabled={!file || connectionStatus !== 'connected'}>Send File</button>
          <div className="progress">
            <div style={{width: `${transferProgress}%`}}></div>
          </div>
          {receivedFile && (
            <button className="btn btn-purple" onClick={downloadFile}>
              Download Received File: {receivedFile.name}
            </button>
          )}
        </div>
      </div>

      {message && <div className="card badge">{message}</div>}

      <div className="card">
        <div className="h2">File Transfer History</div>
        <div className="history">
          {history.length > 0 ? history.map((r, i) => (
            <div key={i} className="card" style={{padding:'1rem', marginBottom:'.75rem'}}>
              <div className="small">File: <strong>{r.fileName}</strong></div>
              <div className="small">Hash: <span className="mono">{r.fileHash}</span></div>
              <div className="small">Sender: <span className="mono">{r.senderId}</span></div>
              <div className="small">Recipient: <span className="mono">{r.recipientId}</span></div>
              <div className="small">Timestamp: {new Date(r.timestamp).toLocaleString()}</div>
            </div>
          )) : <div className="small">No transfer history yet.</div>}
        </div>
      </div>
    </div>
  );
}
