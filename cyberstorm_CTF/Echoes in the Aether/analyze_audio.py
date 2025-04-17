import numpy as np
from scipy.io import wavfile
import matplotlib.pyplot as plt

def plot_spectrogram(filename):
    sample_rate, data = wavfile.read(filename)
    if data.ndim > 1:
        data = data.mean(axis=1)
    data = data / np.max(np.abs(data))
    
    plt.figure(figsize=(12, 6))
    plt.specgram(data, Fs=sample_rate, NFFT=1024, noverlap=512, cmap='viridis')
    plt.title('Spectrogram of Audio File')
    plt.xlabel('Time (s)')
    plt.ylabel('Frequency (Hz)')
    plt.colorbar(label='Intensity (dB)')
    plt.show()

plot_spectrogram("Echoes_in_the_Aether.wav")