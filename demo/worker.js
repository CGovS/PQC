/* Separate worker: only public RSA key and ciphertext are accepted as input. */
importScripts('quantum.js');
self.onmessage = ({data}) => {
  try {
    const started = performance.now();
    const result = QC.crackRSA(data.public, data.ciphertext, {forceQuantum:true,maxAttempts:128});
    const pf = result.shor.pf;
    if (!pf || QC.periodFromMeasurement(pf.measuredC,pf.M,pf.a,pf.N)!==pf.period)
      throw new Error('No verified period-finding trace');
    self.postMessage({ok:true, plaintext:result.plaintext,bytesHex:result.bytesHex,
      d:String(result.d),factors:result.factors,pf,attempts:result.shor.attempts,
      distribution:QC.distribution(pf.a,pf.N),ms:performance.now()-started});
  } catch(e) { self.postMessage({ok:false,error:e.message}); }
};
