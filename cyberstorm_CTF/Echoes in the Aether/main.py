# echo_decoder.py
import numpy as np
from scipy.io import wavfile
import matplotlib.pyplot as plt

# Install missing dependencies first:
# pip install scikit-learn

# --- Part 1: Audio Analysis ---
def plot_analysis(filename):
    sample_rate, data = wavfile.read(filename)
    if data.ndim > 1:
        data = data.mean(axis=1)
    data = data / np.max(np.abs(data))
    
    # Waveform plot
    plt.figure(figsize=(12, 4))
    plt.plot(data[:5*sample_rate])
    plt.title("First 5 Seconds of Audio")
    plt.show()
    
    # Spectrogram plot with error handling
    plt.figure(figsize=(12, 4))
    spec, freqs, t, im = plt.specgram(data, Fs=sample_rate, NFFT=1024, noverlap=512)
    spec = np.where(spec == 0, np.finfo(float).eps, spec)  # Avoid log10(0)
    plt.title('Spectrogram (dB)')
    plt.xlabel('Time (s)')
    plt.ylabel('Frequency (Hz)')
    plt.colorbar()
    plt.show()

# --- Part 2: Frequency Decoding ---
def frequency_decoder(filename):
    from sklearn.cluster import KMeans
    
    sample_rate, data = wavfile.read(filename)
    if data.ndim > 1:
        data = data.mean(axis=1)
    data = data / np.max(np.abs(data))
    
    window_size = 1024
    freqs = []
    
    for i in range(0, len(data)-window_size, window_size//2):
        segment = data[i:i+window_size]
        fft = np.abs(np.fft.rfft(segment * np.hanning(window_size)))
        freq = np.fft.rfftfreq(window_size, d=1/sample_rate)[np.argmax(fft)]
        freqs.append(freq)
    
    # K-Means clustering
    kmeans = KMeans(n_clusters=2)
    clusters = kmeans.fit_predict(np.array(freqs).reshape(-1, 1))
    return ''.join(['1' if c == 1 else '0' for c in clusters])

# --- Part 3: Flag Extraction ---
def extract_flag(binary_str):
    # Try common encodings
    try:
        # 8-bit ASCII
        bytes_data = bytes(int(binary_str[i:i+8], 2) 
                          for i in range(0, len(binary_str), 8))
        decoded = bytes_data.decode('utf-8', errors='replace')
        if 'CTF{' in decoded:
            return decoded.split('}')[0] + '}'
        
        # Hex conversion
        hex_str = hex(int(binary_str, 2))[2:]
        hex_decoded = bytes.fromhex(hex_str).decode('utf-8', errors='replace')
        if 'CTF{' in hex_decoded:
            return hex_decoded.split('}')[0] + '}'
    except:
        pass
    
    # Manual pattern check
    patterns = {
        'CTF{': ['01000011', '01010100', '01000110', '01111011'],
        'flag': ['01100110', '01101100', '01100001', '01100111']
    }
    
    for key, bits in patterns.items():
        if ''.join(bits) in binary_str:
            return f"Found pattern for {key}..."
    
    return "Flag not found automatically. Try manual analysis."

# --- Main Execution ---
if __name__ == '__main__':
    # Step 1: Install dependencies
    try:
        from sklearn.cluster import KMeans
    except ImportError:
        print("\nERROR: Required packages missing!")
        print("Run these commands first:")
        print("pip install scikit-learn")
        exit()
    
    # Step 2: Analyze audio
    plot_analysis("Echoes_in_the_Aether.wav")
    
    # Step 3: Decode binary
    binary_data = frequency_decoder("Echoes_in_the_Aether.wav")
    print("\nFirst 256 bits:", binary_data[:256])
    
    # Step 4: Extract flag
    print("\nDecoding Results:")
    print(extract_flag(binary_data))