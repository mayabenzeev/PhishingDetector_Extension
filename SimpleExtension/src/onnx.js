import * as ort from 'onnxruntime-web';

export async function loadModel() {
  const url = chrome.runtime.getURL("rf_model.onnx");
  const resp = await fetch(url);
  const bytes = await resp.arrayBuffer();
  return await ort.InferenceSession.create(bytes);
}