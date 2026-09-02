import type { Request, Response } from './messages.js';
export async function sendMessage(msg: Request): Promise<Response> {
  return chrome.runtime.sendMessage(msg);
}