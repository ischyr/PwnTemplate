import numpy as np
from PIL import Image

im1 = Image.open("flag.png")
im2 = Image.open("lemur.png")

im1np = np.array(im1)*255
im2np = np.array(im2)*255

result = np.bitwise_xor(im1np, im2np).astype(np.uint8)

Image.fromarray(result).save('result.png')
