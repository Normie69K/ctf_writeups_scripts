from sklearn.cluster import KMeans

def dynamic_threshold_decoder(filename):
    sample_rate, data = wavfile.read(filename)
    if data.ndim > 1:
        data = data.mean(axis=1)
    data = data / np.max(np.abs(data))
    
    # Parameters
    window_size = 1024
    step_size = 512
    freqs = []
    
    for i in range(0, len(data) - window_size, step_size):
        segment = data[i:i+window_size]
        windowed = segment * np.hanning(window_size)
        fft = np.abs(np.fft.rfft(windowed))
        freq = np.fft.rfftfreq(window_size, d=1/sample_rate)
        peak_idx = np.argmax(fft)
        freqs.append(freq[peak_idx])
    
    # Use K-Means to find two frequency clusters
    kmeans = KMeans(n_clusters=2)
    kmeans.fit(np.array(freqs).reshape(-1, 1))
    centers = sorted(kmeans.cluster_centers_.flatten())
    threshold = np.mean(centers)
    
    # Generate binary based on clusters
    binary_str = ''.join(['1' if f > threshold else '0' for f in freqs])
    return binary_str, threshold

binary_data, threshold = dynamic_threshold_decoder("Echoes_in_the_Aether.wav")
print(f"Dynamic Frequency Threshold: {threshold:.2f} Hz")
print("Binary Start:", binary_data[:64])