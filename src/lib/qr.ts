// Vendored jsQR v1.4.0. Source: https://github.com/cozmo/jsQR (Apache-2.0).
// DO NOT load this from the network at runtime.
import jsQR from '../vendor/jsqr.js';

export function decodeQrFromImageData(image: ImageData): string | null {
  const result = jsQR(image.data, image.width, image.height);
  return result ? result.data : null;
}