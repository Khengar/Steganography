from PIL import Image
import numpy as np
from scipy.stats import chisquare
import matplotlib.pyplot as plt
import io

def analyze_image_lsb(image_bytes):
    """
    Performs a Chi-Squared test on the LSBs of an image to detect steganography.
    Returns a simple one-word result and detailed analysis.
    """
    image = Image.open(io.BytesIO(image_bytes))
    
    if image.format == 'JPEG':
        simple_result = "Inconclusive"
        detailed_result = "This is a JPEG file. LSB analysis is unreliable on compressed images."
        return simple_result, detailed_result, None

    image = image.convert('RGB')
    img_arr = np.array(image)
    
    lsbs = img_arr & 1
    flat_lsbs = lsbs.flatten()
    
    observed_freq = np.bincount(flat_lsbs, minlength=2)
    total_bits = len(flat_lsbs)
    expected_freq = [total_bits / 2, total_bits / 2]
    
    chi2_statistic, p_value = chisquare(observed_freq, expected_freq)
    
    fig, ax = plt.subplots()
    ax.bar(['0s', '1s'], observed_freq, color=['blue', 'orange'])
    ax.set_title('Distribution of Least Significant Bits')
    ax.set_ylabel('Frequency')
    
    buf = io.BytesIO()
    fig.savefig(buf, format='png')
    buf.seek(0)
    plot_bytes = buf.getvalue()
    buf.close()
    plt.close(fig)

    is_random = p_value > 0.05
    
    if is_random:
        simple_result = "Clean"
        detailed_result = f"The LSB distribution appears random (p-value: {p_value:.4f})."
    else:
        simple_result = "Suspicious"
        detailed_result = f"The LSB distribution is not random (p-value: {p_value:.4f})."
        
    return simple_result, detailed_result, plot_bytes