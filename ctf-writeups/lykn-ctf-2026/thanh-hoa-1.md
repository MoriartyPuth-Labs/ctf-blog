# Thanh Hoa 1

> **Category:** Forensics (audio spectrogram + appended AES ZIP)&#x20;
>
> **Flag:** `LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}`

(Leetspeak for a Vietnamese meme: "người Thanh Hóa ăn rau má, phá đường tàu" — "Thanh Hóa people eat rau má \[pennywort] and wreck the railway".)

### Challenge Description

Title: **"Thanh Hoa 1: 36 Thanh Hoa"**. Provided a video file `lyknctf.mp4` (\~31.9 MB, 1280x720, \~6m27s) — the Vietnamese MV **"Quê Tôi Thanh Hóa"** by Sting Media. "36" is the Vietnamese vehicle license-plate province code for Thanh Hóa.

### Walkthrough / Reasoning

1. **Triage the container.** `file` → ISO Media / MP4. Inspected the tail bytes and found a ZIP central-directory record naming **`flag.txt`**, with compression method **99 = AES** and the `AE` extra-field marker. So: an **AES-encrypted ZIP is appended to the MP4**, containing `flag.txt`. Needs a password.
   * `zipfile` (stdlib) cannot read AES ZIPs; installed **`pyzipper`** (`pip install pyzipper`).
2. **Hunt the password.** The title/theme guesses ("36ThanhHoa", the on-screen credits, "Quê Tôi Thanh Hóa", the "based on a true story — 15/09/2010" title card, license-plate 36, etc.) were all tried against the AES ZIP and **all failed** (\~200+ candidates).
3. **Pivot to the audio track** (the one artifact not yet examined). Got a working `ffmpeg` via `pip install imageio-ffmpeg` (bundles a static `ffmpeg-win-x86_64` binary), then extracted the audio to WAV and rendered a **spectrogram** (scipy.signal.spectrogram + matplotlib).
4.  **Hidden text in the spectrogram.** In the \~8–12 kHz band there is a **repeating block of text drawn into the spectrogram** (SSTF-style "spectrogram writing"). One clean loop of the letters spells:

    ```
    RAUMAPHATAU
    ```

    (i.e. "RAU MA PHA TAU" — rau má, phá tàu). It looks like gibberish at first, but it is the literal ZIP password.
5.  **Crack.** `pyzipper` with password `RAUMAPHATAU` decrypts `flag.txt`:

    ```
    LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}
    ```

### Key Techniques

* Recognizing an **appended AES ZIP** in a media file (compress\_type 99, `AE` extra field).
* **Spectrogram steganography**: text painted into high-frequency bands of the audio, revealed by a spectrogram. Best read with a narrow frequency window and column overlap; per-column contrast normalization helps when music masks it.
* Using **`imageio-ffmpeg`** to get ffmpeg without a system install; **`pyzipper`** for AES ZIPs.

### Tools Used

* Python 3.11: `pyzipper`, `imageio-ffmpeg`, `scipy`, `numpy`, `matplotlib`, `opencv-python` (cv2)
* ffmpeg (static binary from imageio-ffmpeg) to extract audio

### PoC / Reproduction

See `solve.py` (full pipeline) and `make_spectrogram.py`. Quick crack once you have the password:

```python
import pyzipper
with pyzipper.AESZipFile("lyknctf.mp4") as z:
    print(z.namelist())                                   # ['flag.txt']
    print(z.read("flag.txt", pwd=b"RAUMAPHATAU"))
# b'LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}\n'
```

Extract audio + spectrogram:

```python
import imageio_ffmpeg, subprocess
ff = imageio_ffmpeg.get_ffmpeg_exe()
subprocess.run([ff, "-y", "-i", "lyknctf.mp4", "-vn",
                "-acodec", "pcm_s16le", "-ar", "44100", "-ac", "1", "audio.wav"])

import numpy as np
from scipy.io import wavfile
from scipy import signal
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
sr, data = wavfile.read("audio.wav")
if data.ndim > 1: data = data[:, 0]
f, t, Sxx = signal.spectrogram(data.astype(np.float32), fs=sr, nperseg=4096, noverlap=3900)
Sxx_db = 10*np.log10(Sxx + 1e-10)
mask = (f >= 7500) & (f <= 12800)
plt.figure(figsize=(60, 6))
plt.pcolormesh(t, f[mask], Sxx_db[mask], shading='auto', cmap='inferno')
plt.savefig("spectrogram.png", dpi=100)     # read the letters: RAUMAPHATAU
```

### Reasoning Notes

* The whole "36 / Thanh Hoa / credits / true-story date" material was **misdirection for the password** — none of it worked. The password lived in the audio.
* General lesson for media-file forensics: if an appended encrypted archive resists themed guesses, the password is very often hidden in a _different stream_ of the same file (audio spectrogram, a video frame, ID3/metadata, an LSB plane).
