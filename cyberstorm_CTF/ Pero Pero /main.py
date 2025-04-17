import sys
import numpy as np
from scipy.io import wavfile

def goertzel(samples, sample_rate, target_freq):
    """
    Compute the energy at target_freq using the Goertzel algorithm.
    """
    num_samples = len(samples)
    k = int(0.5 + (num_samples * target_freq / sample_rate))
    omega = (2.0 * np.pi * k) / num_samples
    coeff = 2.0 * np.cos(omega)
    s_prev = 0.0
    s_prev2 = 0.0
    for sample in samples:
        s = sample + coeff * s_prev - s_prev2
        s_prev2 = s_prev
        s_prev = s
    power = s_prev2**2 + s_prev**2 - coeff * s_prev * s_prev2
    return power

def decode_tone(segment, sample_rate):
    """
    Analyze a segment of audio data and return the corresponding DTMF digit.
    """
    # DTMF frequency groups
    low_freqs = [697, 770, 852, 941]
    high_freqs = [1209, 1336, 1477]
    
    # Mapping from (low, high) frequency pair to digit
    dtmf_map = {
        (697, 1209): '1', (697, 1336): '2', (697, 1477): '3',
        (770, 1209): '4', (770, 1336): '5', (770, 1477): '6',
        (852, 1209): '7', (852, 1336): '8', (852, 1477): '9',
        (941, 1209): '*', (941, 1336): '0', (941, 1477): '#'
    }
    
    # Calculate the energy at each DTMF frequency
    low_energy = {f: goertzel(segment, sample_rate, f) for f in low_freqs}
    high_energy = {f: goertzel(segment, sample_rate, f) for f in high_freqs}
    
    # Choose the frequency with the highest energy in each group
    detected_low = max(low_energy, key=low_energy.get)
    detected_high = max(high_energy, key=high_energy.get)
    
    # Return the corresponding digit (or '?' if not found)
    return dtmf_map.get((detected_low, detected_high), '?')

def segment_audio(data, sample_rate, frame_duration=0.05, threshold=0.001):
    """
    Split the audio signal into segments based on energy.
    Each segment should correspond to one DTMF tone.
    """
    frame_size = int(frame_duration * sample_rate)
    energy = np.array([np.sum(data[i:i+frame_size]**2)
                       for i in range(0, len(data), frame_size)])
    
    # Find indices of frames where the energy exceeds the threshold
    indices = np.where(energy > threshold)[0]
    segments = []
    if len(indices) == 0:
        return segments

    # Group consecutive frames into a single segment
    current_group = [indices[0]]
    for idx in indices[1:]:
        if idx == current_group[-1] + 1:
            current_group.append(idx)
        else:
            start = current_group[0] * frame_size
            end = (current_group[-1] + 1) * frame_size
            segments.append((start, end))
            current_group = [idx]
    # Add the final segment
    if current_group:
        start = current_group[0] * frame_size
        end = (current_group[-1] + 1) * frame_size
        segments.append((start, end))
    
    return segments

def main():
    if len(sys.argv) < 2:
        print("Usage: python dtmf_decoder.py your_file.wav")
        sys.exit(1)
    
    filename = sys.argv[1]
    sample_rate, data = wavfile.read(filename)
    print("Sample Rate:", sample_rate)
    
    # Convert to mono if stereo
    if data.ndim > 1:
        data = data.mean(axis=1)
    
    # Normalize the audio data
    data = data / np.max(np.abs(data))
    
    # Segment the audio into individual tone segments
    segments = segment_audio(data, sample_rate, frame_duration=0.05, threshold=0.001)
    print("Found {} tone segment(s)".format(len(segments)))
    
    # Decode each tone segment
    decoded_message = ""
    for i, (start, end) in enumerate(segments):
        segment = data[start:end]
        digit = decode_tone(segment, sample_rate)
        decoded_message += digit
        print(f"Segment {i+1} ({start} to {end}): {digit}")
    
    print("\nDecoded Message:", decoded_message)

if __name__ == '__main__':
    main()
