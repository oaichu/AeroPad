import { describe, it, expect, beforeAll } from 'vitest';
import { decodeQrFromImageData } from '../../src/lib/qr.js';

// happy-dom doesn't provide ImageData; polyfill a minimal one for tests.
beforeAll(() => {
  if (typeof (globalThis as { ImageData?: unknown }).ImageData === 'undefined') {
    class MockImageData {
      data: Uint8ClampedArray;
      width: number;
      height: number;
      constructor(width: number, height: number) {
        this.width = width;
        this.height = height;
        this.data = new Uint8ClampedArray(width * height * 4);
      }
    }
    (globalThis as { ImageData: typeof MockImageData }).ImageData = MockImageData as unknown as typeof ImageData;
  }
});

describe('decodeQrFromImageData', () => {
  it('returns null for a blank image', () => {
    const blank = new ImageData(100, 100);
    expect(decodeQrFromImageData(blank)).toBeNull();
  });
});