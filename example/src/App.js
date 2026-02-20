import "./App.css";
import { useState } from "react";
import { encrypt, decrypt } from "react-aes-gcm-encryption";

function App() {
  const [text, setText] = useState("");
  const [key, setKey] = useState("");
  const [iterations, setIterations] = useState(1000);
  const [saltLength, setSaltLength] = useState(16);
  const [ivLength, setIvLength] = useState(12);
  const [isEncryptMode, setIsEncryptMode] = useState(true);
  const [result, setResult] = useState("");
  const [keyLength, setKeyLength] = useState(256);
  const [tagLength, setTagLength] = useState(128);

  const onActionPress = async () => {
    if (!text || !key) {
      alert("Text and key are required");
      return;
    }

    try {
      if (isEncryptMode) {
        console.log("keyLength:: ", keyLength);
        const encrypted = await encrypt(
          text,
          key,
          keyLength,
          saltLength,
          ivLength,
          tagLength,
          iterations,
        );
        setResult(encrypted);
      } else {
        const decrypted = await decrypt(
          text,
          key,
          keyLength,
          saltLength,
          ivLength,
          tagLength,
          iterations,
        );
        setResult(decrypted);
      }
    } catch (e) {
      console.error(e);
      setResult(e.toString());
    }
  };

  return (
    <div className="page">
      <div className="container">
        <h2 className="title">AES-GCM Crypto Demo</h2>

        <div className="content">
          {/* LEFT COLUMN */}
          <div className="leftColumn">
            <textarea
              className="textarea"
              placeholder={
                isEncryptMode ? "Plain Text" : "Cipher Text (Base64)"
              }
              value={text}
              onChange={(e) => setText(e.target.value)}
            />

            <input
              className="input"
              placeholder="Plain key"
              value={key}
              onChange={(e) => setKey(e.target.value)}
            />
            <div className="field">
              <label htmlFor="keyLength" className="label">
                Select Key Length
              </label>
              <select
                htmlFor="keyLength"
                className="input"
                value={keyLength}
                onChange={(e) => setKeyLength(Number(e.target.value))}
              >
                <option value="256">256</option>
                <option value="128">128</option>
              </select>
            </div>

            <div className="field">
              <label htmlFor="tagLength" className="label">
                Select Tag Length
              </label>
              <select
                className="input"
                id="tagLength"
                value={tagLength}
                onChange={(e) => setTagLength(Number(e.target.value))}
              >
                <option value="128">128</option>
                <option value="120">120</option>
                <option value="112">112</option>
                <option value="104">104</option>
                <option value="96">96</option>
                <option value="64">64</option>
                <option value="32">32</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="saltLength" className="label">
                Salt Length
              </label>
              <input
                id="saltLength"
                className="input"
                type="number"
                placeholder="Salt length"
                value={saltLength}
                onChange={(e) => setSaltLength(Number(e.target.value))}
              />
            </div>
            <div className="field">
              <label htmlFor="ivLength" className="label">
                IV Length
              </label>
              <input
                id="ivLength"
                className="input"
                type="number"
                placeholder="IV length"
                value={ivLength}
                onChange={(e) => setIvLength(Number(e.target.value))}
              />
            </div>
            <div className="field">
              <label htmlFor="iterationCount" className="label">
                Iteration Count
              </label>
              <input
                className="input"
                id="iterationCount"
                type="number"
                placeholder="Iterations count"
                value={iterations}
                onChange={(e) => setIterations(Number(e.target.value))}
              />
            </div>
            <div className="toggleRow">
              <span>Mode: {isEncryptMode ? "Encrypt 🔐" : "Decrypt 🔓"}</span>

              <input
                type="checkbox"
                checked={isEncryptMode}
                onChange={(e) => setIsEncryptMode(e.target.checked)}
              />
            </div>

            <button className="button" onClick={onActionPress}>
              {isEncryptMode ? "Encrypt" : "Decrypt"}
            </button>
          </div>

          {/* RIGHT COLUMN */}
          <div className="rightColumn">
            <h3 className="resultTitle">Result</h3>
            <div className="resultBox">
              {result || "Output appears here..."}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
