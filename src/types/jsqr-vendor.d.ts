// Type declaration for the vendored jsQR v1.4.0 script.
// Source: https://github.com/cozmo/jsQR (Apache-2.0).
declare module '*jsqr.js' {
  interface QrCodeResult {
    data: string;
    location?: {
      topLeftCorner: { x: number; y: number };
      topRightCorner: { x: number; y: number };
      bottomLeftCorner: { x: number; y: number };
      bottomRightCorner: { x: number; y: number };
    };
  }
  interface QrCodeOptions {
    inversionAttempts?: 'attemptBoth' | 'invertFirst' | 'dontInvert' | 'onlyInvert';
  }
  function jsQR(
    data: Uint8ClampedArray,
    width: number,
    height: number,
    options?: QrCodeOptions,
  ): QrCodeResult | null;
  export default jsQR;
}