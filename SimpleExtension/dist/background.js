var tm=Object.defineProperty;var rm=(e,t,r)=>t in e?tm(e,t,{enumerable:!0,configurable:!0,writable:!0,value:r}):e[t]=r;var ys=(e,t,r)=>rm(e,typeof t!="symbol"?t+"":t,r);/*!
 * ONNX Runtime Web v1.22.0
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */var Ea=Object.defineProperty,im=Object.getOwnPropertyDescriptor,am=Object.getOwnPropertyNames,nm=Object.prototype.hasOwnProperty,sm=(e=>typeof require<"u"?require:typeof Proxy<"u"?new Proxy(e,{get:(t,r)=>(typeof require<"u"?require:t)[r]}):e)(function(e){if(typeof require<"u")return require.apply(this,arguments);throw Error('Dynamic require of "'+e+'" is not supported')}),P=(e,t)=>()=>(e&&(t=e(e=0)),t),qt=(e,t)=>{for(var r in t)Ea(e,r,{get:t[r],enumerable:!0})},om=(e,t,r,a)=>{if(t&&typeof t=="object"||typeof t=="function")for(let n of am(t))!nm.call(e,n)&&n!==r&&Ea(e,n,{get:()=>t[n],enumerable:!(a=im(t,n))||a.enumerable});return e},or=e=>om(Ea({},"__esModule",{value:!0}),e),Gt,ct,Mt,bs,Yl,Jl=P(()=>{Gt=new Map,ct=[],Mt=(e,t,r)=>{if(t&&typeof t.init=="function"&&typeof t.createInferenceSessionHandler=="function"){let a=Gt.get(e);if(a===void 0)Gt.set(e,{backend:t,priority:r});else{if(a.priority>r)return;if(a.priority===r&&a.backend!==t)throw new Error(`cannot register backend "${e}" using priority ${r}`)}if(r>=0){let n=ct.indexOf(e);n!==-1&&ct.splice(n,1);for(let i=0;i<ct.length;i++)if(Gt.get(ct[i]).priority<=r){ct.splice(i,0,e);return}ct.push(e)}return}throw new TypeError("not a valid backend")},bs=async e=>{let t=Gt.get(e);if(!t)return"backend not found.";if(t.initialized)return t.backend;if(t.aborted)return t.error;{let r=!!t.initPromise;try{return r||(t.initPromise=t.backend.init(e)),await t.initPromise,t.initialized=!0,t.backend}catch(a){return r||(t.error=`${a}`,t.aborted=!0),t.error}finally{delete t.initPromise}}},Yl=async e=>{let t=e.executionProviders||[],r=t.map(d=>typeof d=="string"?d:d.name),a=r.length===0?ct:r,n,i=[],s=new Set;for(let d of a){let l=await bs(d);typeof l=="string"?i.push({name:d,err:l}):(n||(n=l),n===l&&s.add(d))}if(!n)throw new Error(`no available backend found. ERR: ${i.map(d=>`[${d.name}] ${d.err}`).join(", ")}`);for(let{name:d,err:l}of i)r.includes(d)&&console.warn(`removing requested execution provider "${d}" from session options because it is not available: ${l}`);let u=t.filter(d=>s.has(typeof d=="string"?d:d.name));return[n,new Proxy(e,{get:(d,l)=>l==="executionProviders"?u:Reflect.get(d,l)})]}}),um=P(()=>{Jl()}),ed,lm=P(()=>{ed="1.22.0"}),pi,Pe,td=P(()=>{lm(),pi="warning",Pe={wasm:{},webgl:{},webgpu:{},versions:{common:ed},set logLevel(e){if(e!==void 0){if(typeof e!="string"||["verbose","info","warning","error","fatal"].indexOf(e)===-1)throw new Error(`Unsupported logging level: ${e}`);pi=e}},get logLevel(){return pi}},Object.defineProperty(Pe,"logLevel",{enumerable:!0})}),_e,dm=P(()=>{td(),_e=Pe}),rd,id,pm=P(()=>{rd=(e,t)=>{let r=typeof document<"u"?document.createElement("canvas"):new OffscreenCanvas(1,1);r.width=e.dims[3],r.height=e.dims[2];let a=r.getContext("2d");if(a!=null){let n,i;(t==null?void 0:t.tensorLayout)!==void 0&&t.tensorLayout==="NHWC"?(n=e.dims[2],i=e.dims[3]):(n=e.dims[3],i=e.dims[2]);let s=(t==null?void 0:t.format)!==void 0?t.format:"RGB",u=t==null?void 0:t.norm,d,l;u===void 0||u.mean===void 0?d=[255,255,255,255]:typeof u.mean=="number"?d=[u.mean,u.mean,u.mean,u.mean]:(d=[u.mean[0],u.mean[1],u.mean[2],0],u.mean[3]!==void 0&&(d[3]=u.mean[3])),u===void 0||u.bias===void 0?l=[0,0,0,0]:typeof u.bias=="number"?l=[u.bias,u.bias,u.bias,u.bias]:(l=[u.bias[0],u.bias[1],u.bias[2],0],u.bias[3]!==void 0&&(l[3]=u.bias[3]));let c=i*n,f=0,m=c,g=c*2,_=-1;s==="RGBA"?(f=0,m=c,g=c*2,_=c*3):s==="RGB"?(f=0,m=c,g=c*2):s==="RBG"&&(f=0,g=c,m=c*2);for(let b=0;b<i;b++)for(let x=0;x<n;x++){let $=(e.data[f++]-l[0])*d[0],w=(e.data[m++]-l[1])*d[1],S=(e.data[g++]-l[2])*d[2],k=_===-1?255:(e.data[_++]-l[3])*d[3];a.fillStyle="rgba("+$+","+w+","+S+","+k+")",a.fillRect(x,b,1,1)}if("toDataURL"in r)return r.toDataURL();throw new Error("toDataURL is not supported")}else throw new Error("Can not access image data")},id=(e,t)=>{let r=typeof document<"u"?document.createElement("canvas").getContext("2d"):new OffscreenCanvas(1,1).getContext("2d"),a;if(r!=null){let n,i,s;(t==null?void 0:t.tensorLayout)!==void 0&&t.tensorLayout==="NHWC"?(n=e.dims[2],i=e.dims[1],s=e.dims[3]):(n=e.dims[3],i=e.dims[2],s=e.dims[1]);let u=t!==void 0&&t.format!==void 0?t.format:"RGB",d=t==null?void 0:t.norm,l,c;d===void 0||d.mean===void 0?l=[255,255,255,255]:typeof d.mean=="number"?l=[d.mean,d.mean,d.mean,d.mean]:(l=[d.mean[0],d.mean[1],d.mean[2],255],d.mean[3]!==void 0&&(l[3]=d.mean[3])),d===void 0||d.bias===void 0?c=[0,0,0,0]:typeof d.bias=="number"?c=[d.bias,d.bias,d.bias,d.bias]:(c=[d.bias[0],d.bias[1],d.bias[2],0],d.bias[3]!==void 0&&(c[3]=d.bias[3]));let f=i*n;if(t!==void 0&&(t.format!==void 0&&s===4&&t.format!=="RGBA"||s===3&&t.format!=="RGB"&&t.format!=="BGR"))throw new Error("Tensor format doesn't match input tensor dims");let m=4,g=0,_=1,b=2,x=3,$=0,w=f,S=f*2,k=-1;u==="RGBA"?($=0,w=f,S=f*2,k=f*3):u==="RGB"?($=0,w=f,S=f*2):u==="RBG"&&($=0,S=f,w=f*2),a=r.createImageData(n,i);for(let T=0;T<i*n;g+=m,_+=m,b+=m,x+=m,T++)a.data[g]=(e.data[$++]-c[0])*l[0],a.data[_]=(e.data[w++]-c[1])*l[1],a.data[b]=(e.data[S++]-c[2])*l[2],a.data[x]=k===-1?255:(e.data[k++]-c[3])*l[3]}else throw new Error("Can not access image data");return a}}),wr,ad,nd,sd,od,ud,cm=P(()=>{za(),wr=(e,t)=>{if(e===void 0)throw new Error("Image buffer must be defined");if(t.height===void 0||t.width===void 0)throw new Error("Image height and width must be defined");if(t.tensorLayout==="NHWC")throw new Error("NHWC Tensor layout is not supported yet");let{height:r,width:a}=t,n=t.norm??{mean:255,bias:0},i,s;typeof n.mean=="number"?i=[n.mean,n.mean,n.mean,n.mean]:i=[n.mean[0],n.mean[1],n.mean[2],n.mean[3]??255],typeof n.bias=="number"?s=[n.bias,n.bias,n.bias,n.bias]:s=[n.bias[0],n.bias[1],n.bias[2],n.bias[3]??0];let u=t.format!==void 0?t.format:"RGBA",d=t.tensorFormat!==void 0&&t.tensorFormat!==void 0?t.tensorFormat:"RGB",l=r*a,c=d==="RGBA"?new Float32Array(l*4):new Float32Array(l*3),f=4,m=0,g=1,_=2,b=3,x=0,$=l,w=l*2,S=-1;u==="RGB"&&(f=3,m=0,g=1,_=2,b=-1),d==="RGBA"?S=l*3:d==="RBG"?(x=0,w=l,$=l*2):d==="BGR"&&(w=0,$=l,x=l*2);for(let k=0;k<l;k++,m+=f,_+=f,g+=f,b+=f)c[x++]=(e[m]+s[0])/i[0],c[$++]=(e[g]+s[1])/i[1],c[w++]=(e[_]+s[2])/i[2],S!==-1&&b!==-1&&(c[S++]=(e[b]+s[3])/i[3]);return d==="RGBA"?new Ne("float32",c,[1,4,r,a]):new Ne("float32",c,[1,3,r,a])},ad=async(e,t)=>{let r=typeof HTMLImageElement<"u"&&e instanceof HTMLImageElement,a=typeof ImageData<"u"&&e instanceof ImageData,n=typeof ImageBitmap<"u"&&e instanceof ImageBitmap,i=typeof e=="string",s,u=t??{},d=()=>{if(typeof document<"u")return document.createElement("canvas");if(typeof OffscreenCanvas<"u")return new OffscreenCanvas(1,1);throw new Error("Canvas is not supported")},l=c=>typeof HTMLCanvasElement<"u"&&c instanceof HTMLCanvasElement||c instanceof OffscreenCanvas?c.getContext("2d"):null;if(r){let c=d();c.width=e.width,c.height=e.height;let f=l(c);if(f!=null){let m=e.height,g=e.width;if(t!==void 0&&t.resizedHeight!==void 0&&t.resizedWidth!==void 0&&(m=t.resizedHeight,g=t.resizedWidth),t!==void 0){if(u=t,t.tensorFormat!==void 0)throw new Error("Image input config format must be RGBA for HTMLImageElement");u.tensorFormat="RGBA",u.height=m,u.width=g}else u.tensorFormat="RGBA",u.height=m,u.width=g;f.drawImage(e,0,0),s=f.getImageData(0,0,g,m).data}else throw new Error("Can not access image data")}else if(a){let c,f;if(t!==void 0&&t.resizedWidth!==void 0&&t.resizedHeight!==void 0?(c=t.resizedHeight,f=t.resizedWidth):(c=e.height,f=e.width),t!==void 0&&(u=t),u.format="RGBA",u.height=c,u.width=f,t!==void 0){let m=d();m.width=f,m.height=c;let g=l(m);if(g!=null)g.putImageData(e,0,0),s=g.getImageData(0,0,f,c).data;else throw new Error("Can not access image data")}else s=e.data}else if(n){if(t===void 0)throw new Error("Please provide image config with format for Imagebitmap");let c=d();c.width=e.width,c.height=e.height;let f=l(c);if(f!=null){let m=e.height,g=e.width;return f.drawImage(e,0,0,g,m),s=f.getImageData(0,0,g,m).data,u.height=m,u.width=g,wr(s,u)}else throw new Error("Can not access image data")}else{if(i)return new Promise((c,f)=>{let m=d(),g=l(m);if(!e||!g)return f();let _=new Image;_.crossOrigin="Anonymous",_.src=e,_.onload=()=>{m.width=_.width,m.height=_.height,g.drawImage(_,0,0,m.width,m.height);let b=g.getImageData(0,0,m.width,m.height);u.height=m.height,u.width=m.width,c(wr(b.data,u))}});throw new Error("Input data provided is not supported - aborted tensor creation")}if(s!==void 0)return wr(s,u);throw new Error("Input data provided is not supported - aborted tensor creation")},nd=(e,t)=>{let{width:r,height:a,download:n,dispose:i}=t,s=[1,a,r,4];return new Ne({location:"texture",type:"float32",texture:e,dims:s,download:n,dispose:i})},sd=(e,t)=>{let{dataType:r,dims:a,download:n,dispose:i}=t;return new Ne({location:"gpu-buffer",type:r??"float32",gpuBuffer:e,dims:a,download:n,dispose:i})},od=(e,t)=>{let{dataType:r,dims:a,download:n,dispose:i}=t;return new Ne({location:"ml-tensor",type:r??"float32",mlTensor:e,dims:a,download:n,dispose:i})},ud=(e,t,r)=>new Ne({location:"cpu-pinned",type:e,data:t,dims:r??[t.length]})}),kt,tr,ci,ld,fm=P(()=>{kt=new Map([["float32",Float32Array],["uint8",Uint8Array],["int8",Int8Array],["uint16",Uint16Array],["int16",Int16Array],["int32",Int32Array],["bool",Uint8Array],["float64",Float64Array],["uint32",Uint32Array],["int4",Uint8Array],["uint4",Uint8Array]]),tr=new Map([[Float32Array,"float32"],[Uint8Array,"uint8"],[Int8Array,"int8"],[Uint16Array,"uint16"],[Int16Array,"int16"],[Int32Array,"int32"],[Float64Array,"float64"],[Uint32Array,"uint32"]]),ci=!1,ld=()=>{if(!ci){ci=!0;let e=typeof BigInt64Array<"u"&&BigInt64Array.from,t=typeof BigUint64Array<"u"&&BigUint64Array.from,r=globalThis.Float16Array,a=typeof r<"u"&&r.from;e&&(kt.set("int64",BigInt64Array),tr.set(BigInt64Array,"int64")),t&&(kt.set("uint64",BigUint64Array),tr.set(BigUint64Array,"uint64")),a?(kt.set("float16",r),tr.set(r,"float16")):kt.set("float16",Uint16Array)}}}),dd,pd,hm=P(()=>{za(),dd=e=>{let t=1;for(let r=0;r<e.length;r++){let a=e[r];if(typeof a!="number"||!Number.isSafeInteger(a))throw new TypeError(`dims[${r}] must be an integer, got: ${a}`);if(a<0)throw new RangeError(`dims[${r}] must be a non-negative integer, got: ${a}`);t*=a}return t},pd=(e,t)=>{switch(e.location){case"cpu":return new Ne(e.type,e.data,t);case"cpu-pinned":return new Ne({location:"cpu-pinned",data:e.data,type:e.type,dims:t});case"texture":return new Ne({location:"texture",texture:e.texture,type:e.type,dims:t});case"gpu-buffer":return new Ne({location:"gpu-buffer",gpuBuffer:e.gpuBuffer,type:e.type,dims:t});case"ml-tensor":return new Ne({location:"ml-tensor",mlTensor:e.mlTensor,type:e.type,dims:t});default:throw new Error(`tensorReshape: tensor location ${e.location} is not supported`)}}}),Ne,za=P(()=>{pm(),cm(),fm(),hm(),Ne=class{constructor(e,t,r){ld();let a,n;if(typeof e=="object"&&"location"in e)switch(this.dataLocation=e.location,a=e.type,n=e.dims,e.location){case"cpu-pinned":{let s=kt.get(a);if(!s)throw new TypeError(`unsupported type "${a}" to create tensor from pinned buffer`);if(!(e.data instanceof s))throw new TypeError(`buffer should be of type ${s.name}`);this.cpuData=e.data;break}case"texture":{if(a!=="float32")throw new TypeError(`unsupported type "${a}" to create tensor from texture`);this.gpuTextureData=e.texture,this.downloader=e.download,this.disposer=e.dispose;break}case"gpu-buffer":{if(a!=="float32"&&a!=="float16"&&a!=="int32"&&a!=="int64"&&a!=="uint32"&&a!=="uint8"&&a!=="bool"&&a!=="uint4"&&a!=="int4")throw new TypeError(`unsupported type "${a}" to create tensor from gpu buffer`);this.gpuBufferData=e.gpuBuffer,this.downloader=e.download,this.disposer=e.dispose;break}case"ml-tensor":{if(a!=="float32"&&a!=="float16"&&a!=="int32"&&a!=="int64"&&a!=="uint32"&&a!=="uint64"&&a!=="int8"&&a!=="uint8"&&a!=="bool"&&a!=="uint4"&&a!=="int4")throw new TypeError(`unsupported type "${a}" to create tensor from MLTensor`);this.mlTensorData=e.mlTensor,this.downloader=e.download,this.disposer=e.dispose;break}default:throw new Error(`Tensor constructor: unsupported location '${this.dataLocation}'`)}else{let s,u;if(typeof e=="string")if(a=e,u=r,e==="string"){if(!Array.isArray(t))throw new TypeError("A string tensor's data must be a string array.");s=t}else{let d=kt.get(e);if(d===void 0)throw new TypeError(`Unsupported tensor type: ${e}.`);if(Array.isArray(t)){if(e==="float16"&&d===Uint16Array||e==="uint4"||e==="int4")throw new TypeError(`Creating a ${e} tensor from number array is not supported. Please use ${d.name} as data.`);e==="uint64"||e==="int64"?s=d.from(t,BigInt):s=d.from(t)}else if(t instanceof d)s=t;else if(t instanceof Uint8ClampedArray)if(e==="uint8")s=Uint8Array.from(t);else throw new TypeError("A Uint8ClampedArray tensor's data must be type of uint8");else if(e==="float16"&&t instanceof Uint16Array&&d!==Uint16Array)s=new globalThis.Float16Array(t.buffer,t.byteOffset,t.length);else throw new TypeError(`A ${a} tensor's data must be type of ${d}`)}else if(u=t,Array.isArray(e)){if(e.length===0)throw new TypeError("Tensor type cannot be inferred from an empty array.");let d=typeof e[0];if(d==="string")a="string",s=e;else if(d==="boolean")a="bool",s=Uint8Array.from(e);else throw new TypeError(`Invalid element type of data array: ${d}.`)}else if(e instanceof Uint8ClampedArray)a="uint8",s=Uint8Array.from(e);else{let d=tr.get(e.constructor);if(d===void 0)throw new TypeError(`Unsupported type for tensor data: ${e.constructor}.`);a=d,s=e}if(u===void 0)u=[s.length];else if(!Array.isArray(u))throw new TypeError("A tensor's dims must be a number array");n=u,this.cpuData=s,this.dataLocation="cpu"}let i=dd(n);if(this.cpuData&&i!==this.cpuData.length&&!((a==="uint4"||a==="int4")&&Math.ceil(i/2)===this.cpuData.length))throw new Error(`Tensor's size(${i}) does not match data length(${this.cpuData.length}).`);this.type=a,this.dims=n,this.size=i}static async fromImage(e,t){return ad(e,t)}static fromTexture(e,t){return nd(e,t)}static fromGpuBuffer(e,t){return sd(e,t)}static fromMLTensor(e,t){return od(e,t)}static fromPinnedBuffer(e,t,r){return ud(e,t,r)}toDataURL(e){return rd(this,e)}toImageData(e){return id(this,e)}get data(){if(this.ensureValid(),!this.cpuData)throw new Error("The data is not on CPU. Use `getData()` to download GPU data to CPU, or use `texture` or `gpuBuffer` property to access the GPU data directly.");return this.cpuData}get location(){return this.dataLocation}get texture(){if(this.ensureValid(),!this.gpuTextureData)throw new Error("The data is not stored as a WebGL texture.");return this.gpuTextureData}get gpuBuffer(){if(this.ensureValid(),!this.gpuBufferData)throw new Error("The data is not stored as a WebGPU buffer.");return this.gpuBufferData}get mlTensor(){if(this.ensureValid(),!this.mlTensorData)throw new Error("The data is not stored as a WebNN MLTensor.");return this.mlTensorData}async getData(e){switch(this.ensureValid(),this.dataLocation){case"cpu":case"cpu-pinned":return this.data;case"texture":case"gpu-buffer":case"ml-tensor":{if(!this.downloader)throw new Error("The current tensor is not created with a specified data downloader.");if(this.isDownloading)throw new Error("The current tensor is being downloaded.");try{this.isDownloading=!0;let t=await this.downloader();return this.downloader=void 0,this.dataLocation="cpu",this.cpuData=t,e&&this.disposer&&(this.disposer(),this.disposer=void 0),t}finally{this.isDownloading=!1}}default:throw new Error(`cannot get data from location: ${this.dataLocation}`)}}dispose(){if(this.isDownloading)throw new Error("The current tensor is being downloaded.");this.disposer&&(this.disposer(),this.disposer=void 0),this.cpuData=void 0,this.gpuTextureData=void 0,this.gpuBufferData=void 0,this.mlTensorData=void 0,this.downloader=void 0,this.isDownloading=void 0,this.dataLocation="none"}ensureValid(){if(this.dataLocation==="none")throw new Error("The tensor is disposed.")}reshape(e){if(this.ensureValid(),this.downloader||this.disposer)throw new Error("Cannot reshape a tensor that owns GPU resource.");return pd(this,e)}}}),Ye,cd=P(()=>{za(),Ye=Ne}),Nr,fi,Je,Fe,fd=P(()=>{td(),Nr=(e,t)=>{(typeof Pe.trace>"u"?!Pe.wasm.trace:!Pe.trace)||console.timeStamp(`${e}::ORT::${t}`)},fi=(e,t)=>{var n;let r=((n=new Error().stack)==null?void 0:n.split(/\r\n|\r|\n/g))||[],a=!1;for(let i=0;i<r.length;i++){if(a&&!r[i].includes("TRACE_FUNC")){let s=`FUNC_${e}::${r[i].trim().split(" ")[1]}`;t&&(s+=`::${t}`),Nr("CPU",s);return}r[i].includes("TRACE_FUNC")&&(a=!0)}},Je=e=>{(typeof Pe.trace>"u"?!Pe.wasm.trace:!Pe.trace)||fi("BEGIN",e)},Fe=e=>{(typeof Pe.trace>"u"?!Pe.wasm.trace:!Pe.trace)||fi("END",e)}}),hd,mm=P(()=>{Jl(),cd(),fd(),hd=class md{constructor(t){this.handler=t}async run(t,r,a){Je();let n={},i={};if(typeof t!="object"||t===null||t instanceof Ye||Array.isArray(t))throw new TypeError("'feeds' must be an object that use input names as keys and OnnxValue as corresponding values.");let s=!0;if(typeof r=="object"){if(r===null)throw new TypeError("Unexpected argument[1]: cannot be null.");if(r instanceof Ye)throw new TypeError("'fetches' cannot be a Tensor");if(Array.isArray(r)){if(r.length===0)throw new TypeError("'fetches' cannot be an empty array.");s=!1;for(let l of r){if(typeof l!="string")throw new TypeError("'fetches' must be a string array or an object.");if(this.outputNames.indexOf(l)===-1)throw new RangeError(`'fetches' contains invalid output name: ${l}.`);n[l]=null}if(typeof a=="object"&&a!==null)i=a;else if(typeof a<"u")throw new TypeError("'options' must be an object.")}else{let l=!1,c=Object.getOwnPropertyNames(r);for(let f of this.outputNames)if(c.indexOf(f)!==-1){let m=r[f];(m===null||m instanceof Ye)&&(l=!0,s=!1,n[f]=m)}if(l){if(typeof a=="object"&&a!==null)i=a;else if(typeof a<"u")throw new TypeError("'options' must be an object.")}else i=r}}else if(typeof r<"u")throw new TypeError("Unexpected argument[1]: must be 'fetches' or 'options'.");for(let l of this.inputNames)if(typeof t[l]>"u")throw new Error(`input '${l}' is missing in 'feeds'.`);if(s)for(let l of this.outputNames)n[l]=null;let u=await this.handler.run(t,n,i),d={};for(let l in u)if(Object.hasOwnProperty.call(u,l)){let c=u[l];c instanceof Ye?d[l]=c:d[l]=new Ye(c.type,c.data,c.dims)}return Fe(),d}async release(){return this.handler.dispose()}static async create(t,r,a,n){Je();let i,s={};if(typeof t=="string"){if(i=t,typeof r=="object"&&r!==null)s=r;else if(typeof r<"u")throw new TypeError("'options' must be an object.")}else if(t instanceof Uint8Array){if(i=t,typeof r=="object"&&r!==null)s=r;else if(typeof r<"u")throw new TypeError("'options' must be an object.")}else if(t instanceof ArrayBuffer||typeof SharedArrayBuffer<"u"&&t instanceof SharedArrayBuffer){let c=t,f=0,m=t.byteLength;if(typeof r=="object"&&r!==null)s=r;else if(typeof r=="number"){if(f=r,!Number.isSafeInteger(f))throw new RangeError("'byteOffset' must be an integer.");if(f<0||f>=c.byteLength)throw new RangeError(`'byteOffset' is out of range [0, ${c.byteLength}).`);if(m=t.byteLength-f,typeof a=="number"){if(m=a,!Number.isSafeInteger(m))throw new RangeError("'byteLength' must be an integer.");if(m<=0||f+m>c.byteLength)throw new RangeError(`'byteLength' is out of range (0, ${c.byteLength-f}].`);if(typeof n=="object"&&n!==null)s=n;else if(typeof n<"u")throw new TypeError("'options' must be an object.")}else if(typeof a<"u")throw new TypeError("'byteLength' must be a number.")}else if(typeof r<"u")throw new TypeError("'options' must be an object.");i=new Uint8Array(c,f,m)}else throw new TypeError("Unexpected argument[0]: must be 'path' or 'buffer'.");let[u,d]=await Yl(s),l=await u.createInferenceSessionHandler(i,d);return Fe(),new md(l)}startProfiling(){this.handler.startProfiling()}endProfiling(){this.handler.endProfiling()}get inputNames(){return this.handler.inputNames}get outputNames(){return this.handler.outputNames}get inputMetadata(){return this.handler.inputMetadata}get outputMetadata(){return this.handler.outputMetadata}}}),Ca,gm=P(()=>{mm(),Ca=hd}),_m=P(()=>{}),ym=P(()=>{}),bm=P(()=>{}),wm=P(()=>{}),$m={};qt($m,{InferenceSession:()=>Ca,TRACE:()=>Nr,TRACE_FUNC_BEGIN:()=>Je,TRACE_FUNC_END:()=>Fe,Tensor:()=>Ye,env:()=>_e,registerBackend:()=>Mt});var je=P(()=>{um(),dm(),gm(),cd(),_m(),ym(),fd(),bm(),wm()}),Oa=P(()=>{}),gd={};qt(gd,{default:()=>_d});var hi,mi,_d,vm=P(()=>{var e;xf(),Ct(),Aa(),hi="ort-wasm-proxy-worker",mi=((e=globalThis.self)==null?void 0:e.name)===hi,mi&&(self.onmessage=t=>{let{type:r,in:a}=t.data;try{switch(r){case"init-wasm":Ba(a.wasm).then(()=>{Qa(a).then(()=>{postMessage({type:r})},n=>{postMessage({type:r,err:n})})},n=>{postMessage({type:r,err:n})});break;case"init-ep":{let{epName:n,env:i}=a;Xa(i,n).then(()=>{postMessage({type:r})},s=>{postMessage({type:r,err:s})});break}case"copy-from":{let{buffer:n}=a,i=Vr(n);postMessage({type:r,out:i});break}case"create":{let{model:n,options:i}=a;Ya(n,i).then(s=>{postMessage({type:r,out:s})},s=>{postMessage({type:r,err:s})});break}case"release":Ja(a),postMessage({type:r});break;case"run":{let{sessionId:n,inputIndices:i,inputs:s,outputIndices:u,options:d}=a;en(n,i,s,u,new Array(u.length).fill(null),d).then(l=>{l.some(c=>c[3]!=="cpu")?postMessage({type:r,err:"Proxy does not support non-cpu tensor location."}):postMessage({type:r,out:l},rn([...s,...l]))},l=>{postMessage({type:r,err:l})});break}case"end-profiling":tn(a),postMessage({type:r});break;default:}}catch(n){postMessage({type:r,err:n})}}),_d=mi?null:t=>new Worker(t??Re,{type:"module",name:hi})}),yd={};qt(yd,{default:()=>bd});var gi,_i,bd,ws,xm=P(()=>{var e,t;_i=(gi=import.meta.url,async function(r={}){var _s;var a,n,i=r,s=new Promise((o,p)=>{a=o,n=p}),u=typeof window=="object",d=typeof WorkerGlobalScope<"u",l=d&&((_s=self.name)==null?void 0:_s.startsWith("em-pthread"));i.mountExternalData=(o,p)=>{o.startsWith("./")&&(o=o.substring(2)),(i.Fb||(i.Fb=new Map)).set(o,p)},i.unmountExternalData=()=>{delete i.Fb};var c=globalThis.SharedArrayBuffer??new WebAssembly.Memory({initial:0,maximum:0,qc:!0}).buffer.constructor;let f=o=>async(...p)=>{var h;try{if(i.Gb)throw Error("Session already started");let y=i.Gb={ec:p[0],errors:[]},v=await o(...p);if(i.Gb!==y)throw Error("Session mismatch");(h=i.Kb)==null||h.flush();let I=y.errors;if(0<I.length){let B=await Promise.all(I);if(B=B.filter(D=>D),0<B.length)throw Error(B.join(`
`))}return v}finally{i.Gb=null}};i.jsepInit=(o,p)=>{if(o==="webgpu"){[i.Kb,i.Vb,i.Zb,i.Lb,i.Yb,i.kb,i.$b,i.bc,i.Wb,i.Xb,i.ac]=p;let h=i.Kb;i.jsepRegisterBuffer=(y,v,I,B)=>h.registerBuffer(y,v,I,B),i.jsepGetBuffer=y=>h.getBuffer(y),i.jsepCreateDownloader=(y,v,I)=>h.createDownloader(y,v,I),i.jsepOnCreateSession=y=>{h.onCreateSession(y)},i.jsepOnReleaseSession=y=>{h.onReleaseSession(y)},i.jsepOnRunStart=y=>h.onRunStart(y),i.cc=(y,v)=>{h.upload(y,v)}}else if(o==="webnn"){let h=p[0];[i.oc,i.Ob,i.webnnEnsureTensor,i.Pb,i.webnnDownloadTensor]=p.slice(1),i.webnnReleaseTensorId=i.Ob,i.webnnUploadTensor=i.Pb,i.webnnOnRunStart=y=>h.onRunStart(y),i.webnnOnRunEnd=h.onRunEnd.bind(h),i.webnnRegisterMLContext=(y,v)=>{h.registerMLContext(y,v)},i.webnnOnReleaseSession=y=>{h.onReleaseSession(y)},i.webnnCreateMLTensorDownloader=(y,v)=>h.createMLTensorDownloader(y,v),i.webnnRegisterMLTensor=(y,v,I,B)=>h.registerMLTensor(y,v,I,B),i.webnnCreateMLContext=y=>h.createMLContext(y),i.webnnRegisterMLConstant=(y,v,I,B,D,W)=>h.registerMLConstant(y,v,I,B,D,i.Fb,W),i.webnnRegisterGraphInput=h.registerGraphInput.bind(h),i.webnnIsGraphInput=h.isGraphInput.bind(h),i.webnnRegisterGraphOutput=h.registerGraphOutput.bind(h),i.webnnIsGraphOutput=h.isGraphOutput.bind(h),i.webnnCreateTemporaryTensor=h.createTemporaryTensor.bind(h),i.webnnIsGraphInputOutputTypeSupported=h.isGraphInputOutputTypeSupported.bind(h)}};let m=()=>{let o=(p,h,y)=>(...v)=>{let I=Ze,B=h==null?void 0:h();v=p(...v);let D=h==null?void 0:h();return B!==D&&(p=D,y(B),h=y=null),Ze!=I?new Promise((W,K)=>{ii={resolve:W,reject:K}}):v};(()=>{for(let p of["_OrtAppendExecutionProvider","_OrtCreateSession","_OrtRun","_OrtRunWithBinding","_OrtBindInput"])i[p]=o(i[p],()=>i[p],h=>i[p]=h)})(),f!==void 0&&(i._OrtRun=f(i._OrtRun),i._OrtRunWithBinding=f(i._OrtRunWithBinding)),m=void 0};i.asyncInit=()=>{m==null||m()};var g,_,b=Object.assign({},i),x=(o,p)=>{throw p},$="";(u||d)&&(d?$=self.location.href:typeof document<"u"&&document.currentScript&&($=document.currentScript.src),gi&&($=gi),$=$.startsWith("blob:")?"":$.slice(0,$.replace(/[?#].*/,"").lastIndexOf("/")+1),d&&(_=o=>{var p=new XMLHttpRequest;return p.open("GET",o,!1),p.responseType="arraybuffer",p.send(null),new Uint8Array(p.response)}),g=async o=>{if(N(o))return new Promise((h,y)=>{var v=new XMLHttpRequest;v.open("GET",o,!0),v.responseType="arraybuffer",v.onload=()=>{v.status==200||v.status==0&&v.response?h(v.response):y(v.status)},v.onerror=y,v.send(null)});var p=await fetch(o,{credentials:"same-origin"});if(p.ok)return p.arrayBuffer();throw Error(p.status+" : "+p.url)});var w=console.log.bind(console),S=console.error.bind(console),k=w,T=S;Object.assign(i,b),b=null;var E,z,C,A,q,X,G,Z,oe,re,L,ie,F,Y=i.wasmBinary,ye=!1,N=o=>o.startsWith("file://");function U(){return E.buffer!=A.buffer&&fe(),A}function V(){return E.buffer!=A.buffer&&fe(),q}function te(){return E.buffer!=A.buffer&&fe(),X}function Te(){return E.buffer!=A.buffer&&fe(),G}function M(){return E.buffer!=A.buffer&&fe(),Z}function ce(){return E.buffer!=A.buffer&&fe(),oe}function At(){return E.buffer!=A.buffer&&fe(),re}function ze(){return E.buffer!=A.buffer&&fe(),F}if(l){let o=function(p){try{var h=p.data,y=h.Cb;if(y==="load"){let v=[];self.onmessage=I=>v.push(I),self.startWorker=()=>{postMessage({Cb:"loaded"});for(let I of v)o(I);self.onmessage=o};for(let I of h.Sb)i[I]&&!i[I].proxy||(i[I]=(...B)=>{postMessage({Cb:"callHandler",Rb:I,args:B})},I=="print"&&(k=i[I]),I=="printErr"&&(T=i[I]));E=h.lc,fe(),Ue(h.mc)}else if(y==="run"){Df(h.Bb),oi(h.Bb,0,0,1,0,0),pn(),ti(h.Bb),et||(ns(),et=!0);try{Pf(h.hc,h.Ib)}catch(v){if(v!="unwind")throw v}}else h.target!=="setimmediate"&&(y==="checkMailbox"?et&&lr():y&&(T(`worker: received unknown command ${y}`),T(h)))}catch(v){throw ss(),v}};var Ue,et=!1;T=function(...p){p=p.join(" "),console.error(p)},self.alert=function(...p){postMessage({Cb:"alert",text:p.join(" "),jc:_r()})},self.onunhandledrejection=p=>{throw p.reason||p},self.onmessage=o}function fe(){var o=E.buffer;i.HEAP8=A=new Int8Array(o),i.HEAP16=X=new Int16Array(o),i.HEAPU8=q=new Uint8Array(o),i.HEAPU16=G=new Uint16Array(o),i.HEAP32=Z=new Int32Array(o),i.HEAPU32=oe=new Uint32Array(o),i.HEAPF32=re=new Float32Array(o),i.HEAPF64=F=new Float64Array(o),i.HEAP64=L=new BigInt64Array(o),i.HEAPU64=ie=new BigUint64Array(o)}function we(){l?startWorker(i):J.Da()}l||(E=new WebAssembly.Memory({initial:256,maximum:65536,shared:!0}),fe());var Be,_t=0,yt=null;function an(){if(--_t==0&&yt){var o=yt;yt=null,o()}}function st(o){throw T(o="Aborted("+o+")"),ye=!0,o=new WebAssembly.RuntimeError(o+". Build with -sASSERTIONS for more info."),n(o),o}function nn(){return{a:{L:Mf,Aa:Nf,b:qf,$:mn,A:yn,pa:bn,X:$n,Z:vn,qa:xn,na:kn,ga:Sn,ma:Tn,J:In,Y:En,V:zn,oa:Cn,W:On,va:Wf,E:Vf,Q:Lf,O:Hf,D:jf,v:Kf,r:Zf,P:Qf,z:ih,R:ah,ja:nh,T:sh,aa:oh,M:uh,F:lh,ia:ti,sa:dh,t:ph,Ca:ch,w:mh,o:gh,m:yh,c:Yr,Ba:bh,n:wh,j:xh,u:kh,p:Sh,f:Th,s:Ih,l:Eh,e:zh,k:Ch,h:Oh,g:Ah,d:Bh,da:Rh,ea:Nh,fa:Mh,ba:Hn,ca:Fn,N:jn,xa:Ph,ua:qh,i:Wh,C:Vh,G:Lh,ta:Uh,x:Gh,ra:Hh,U:Fh,q:Dh,y:jh,K:Kh,S:Zh,za:Qh,ya:Xh,ka:Xn,la:Yn,_:Kr,B:Jn,I:es,ha:ts,H:rs,a:E,wa:jr}}}var Gr={840156:(o,p,h,y,v)=>{if(i===void 0||!i.Fb)return 1;if((o=xe(Number(o>>>0))).startsWith("./")&&(o=o.substring(2)),!(o=i.Fb.get(o)))return 2;if(p=Number(p>>>0),h=Number(h>>>0),y=Number(y>>>0),p+h>o.byteLength)return 3;try{let I=o.subarray(p,p+h);switch(v){case 0:V().set(I,y>>>0);break;case 1:i.nc?i.nc(y,I):i.cc(y,I);break;default:return 4}return 0}catch{return 4}},840980:(o,p,h)=>{i.Pb(o,V().subarray(p>>>0,p+h>>>0))},841044:()=>i.oc(),841086:o=>{i.Ob(o)},841123:()=>{i.Wb()},841154:()=>{i.Xb()},841183:()=>{i.ac()},841208:o=>i.Vb(o),841241:o=>i.Zb(o),841273:(o,p,h)=>{i.Lb(Number(o),Number(p),Number(h),!0)},841336:(o,p,h)=>{i.Lb(Number(o),Number(p),Number(h))},841393:()=>typeof wasmOffsetConverter<"u",841450:o=>{i.kb("Abs",o,void 0)},841501:o=>{i.kb("Neg",o,void 0)},841552:o=>{i.kb("Floor",o,void 0)},841605:o=>{i.kb("Ceil",o,void 0)},841657:o=>{i.kb("Reciprocal",o,void 0)},841715:o=>{i.kb("Sqrt",o,void 0)},841767:o=>{i.kb("Exp",o,void 0)},841818:o=>{i.kb("Erf",o,void 0)},841869:o=>{i.kb("Sigmoid",o,void 0)},841924:(o,p,h)=>{i.kb("HardSigmoid",o,{alpha:p,beta:h})},842003:o=>{i.kb("Log",o,void 0)},842054:o=>{i.kb("Sin",o,void 0)},842105:o=>{i.kb("Cos",o,void 0)},842156:o=>{i.kb("Tan",o,void 0)},842207:o=>{i.kb("Asin",o,void 0)},842259:o=>{i.kb("Acos",o,void 0)},842311:o=>{i.kb("Atan",o,void 0)},842363:o=>{i.kb("Sinh",o,void 0)},842415:o=>{i.kb("Cosh",o,void 0)},842467:o=>{i.kb("Asinh",o,void 0)},842520:o=>{i.kb("Acosh",o,void 0)},842573:o=>{i.kb("Atanh",o,void 0)},842626:o=>{i.kb("Tanh",o,void 0)},842678:o=>{i.kb("Not",o,void 0)},842729:(o,p,h)=>{i.kb("Clip",o,{min:p,max:h})},842798:o=>{i.kb("Clip",o,void 0)},842850:(o,p)=>{i.kb("Elu",o,{alpha:p})},842908:o=>{i.kb("Gelu",o,void 0)},842960:o=>{i.kb("Relu",o,void 0)},843012:(o,p)=>{i.kb("LeakyRelu",o,{alpha:p})},843076:(o,p)=>{i.kb("ThresholdedRelu",o,{alpha:p})},843146:(o,p)=>{i.kb("Cast",o,{to:p})},843204:o=>{i.kb("Add",o,void 0)},843255:o=>{i.kb("Sub",o,void 0)},843306:o=>{i.kb("Mul",o,void 0)},843357:o=>{i.kb("Div",o,void 0)},843408:o=>{i.kb("Pow",o,void 0)},843459:o=>{i.kb("Equal",o,void 0)},843512:o=>{i.kb("Greater",o,void 0)},843567:o=>{i.kb("GreaterOrEqual",o,void 0)},843629:o=>{i.kb("Less",o,void 0)},843681:o=>{i.kb("LessOrEqual",o,void 0)},843740:(o,p,h,y,v)=>{i.kb("ReduceMean",o,{keepDims:!!p,noopWithEmptyAxes:!!h,axes:y?Array.from(M().subarray(Number(y)>>>0,Number(v)>>>0)):[]})},843915:(o,p,h,y,v)=>{i.kb("ReduceMax",o,{keepDims:!!p,noopWithEmptyAxes:!!h,axes:y?Array.from(M().subarray(Number(y)>>>0,Number(v)>>>0)):[]})},844089:(o,p,h,y,v)=>{i.kb("ReduceMin",o,{keepDims:!!p,noopWithEmptyAxes:!!h,axes:y?Array.from(M().subarray(Number(y)>>>0,Number(v)>>>0)):[]})},844263:(o,p,h,y,v)=>{i.kb("ReduceProd",o,{keepDims:!!p,noopWithEmptyAxes:!!h,axes:y?Array.from(M().subarray(Number(y)>>>0,Number(v)>>>0)):[]})},844438:(o,p,h,y,v)=>{i.kb("ReduceSum",o,{keepDims:!!p,noopWithEmptyAxes:!!h,axes:y?Array.from(M().subarray(Number(y)>>>0,Number(v)>>>0)):[]})},844612:(o,p,h,y,v)=>{i.kb("ReduceL1",o,{keepDims:!!p,noopWithEmptyAxes:!!h,axes:y?Array.from(M().subarray(Number(y)>>>0,Number(v)>>>0)):[]})},844785:(o,p,h,y,v)=>{i.kb("ReduceL2",o,{keepDims:!!p,noopWithEmptyAxes:!!h,axes:y?Array.from(M().subarray(Number(y)>>>0,Number(v)>>>0)):[]})},844958:(o,p,h,y,v)=>{i.kb("ReduceLogSum",o,{keepDims:!!p,noopWithEmptyAxes:!!h,axes:y?Array.from(M().subarray(Number(y)>>>0,Number(v)>>>0)):[]})},845135:(o,p,h,y,v)=>{i.kb("ReduceSumSquare",o,{keepDims:!!p,noopWithEmptyAxes:!!h,axes:y?Array.from(M().subarray(Number(y)>>>0,Number(v)>>>0)):[]})},845315:(o,p,h,y,v)=>{i.kb("ReduceLogSumExp",o,{keepDims:!!p,noopWithEmptyAxes:!!h,axes:y?Array.from(M().subarray(Number(y)>>>0,Number(v)>>>0)):[]})},845495:o=>{i.kb("Where",o,void 0)},845548:(o,p,h)=>{i.kb("Transpose",o,{perm:p?Array.from(M().subarray(Number(p)>>>0,Number(h)>>>0)):[]})},845672:(o,p,h,y)=>{i.kb("DepthToSpace",o,{blocksize:p,mode:xe(h),format:y?"NHWC":"NCHW"})},845805:(o,p,h,y)=>{i.kb("DepthToSpace",o,{blocksize:p,mode:xe(h),format:y?"NHWC":"NCHW"})},845938:(o,p,h,y,v,I,B,D,W,K,se,le,me,Ie,Rt)=>{i.kb("ConvTranspose",o,{format:W?"NHWC":"NCHW",autoPad:p,dilations:[h],group:y,kernelShape:[v],pads:[I,B],strides:[D],wIsConst:()=>!!U()[K>>>0],outputPadding:se?Array.from(M().subarray(Number(se)>>>0,Number(le)>>>0)):[],outputShape:me?Array.from(M().subarray(Number(me)>>>0,Number(Ie)>>>0)):[],activation:xe(Rt)})},846371:(o,p,h,y,v,I,B,D,W,K,se,le,me,Ie)=>{i.kb("ConvTranspose",o,{format:D?"NHWC":"NCHW",autoPad:p,dilations:Array.from(M().subarray(Number(h)>>>0,2+(Number(h)>>>0)>>>0)),group:y,kernelShape:Array.from(M().subarray(Number(v)>>>0,2+(Number(v)>>>0)>>>0)),pads:Array.from(M().subarray(Number(I)>>>0,4+(Number(I)>>>0)>>>0)),strides:Array.from(M().subarray(Number(B)>>>0,2+(Number(B)>>>0)>>>0)),wIsConst:()=>!!U()[W>>>0],outputPadding:K?Array.from(M().subarray(Number(K)>>>0,Number(se)>>>0)):[],outputShape:le?Array.from(M().subarray(Number(le)>>>0,Number(me)>>>0)):[],activation:xe(Ie)})},847032:(o,p,h,y,v,I,B,D,W,K,se,le,me,Ie,Rt)=>{i.kb("ConvTranspose",o,{format:W?"NHWC":"NCHW",autoPad:p,dilations:[h],group:y,kernelShape:[v],pads:[I,B],strides:[D],wIsConst:()=>!!U()[K>>>0],outputPadding:se?Array.from(M().subarray(Number(se)>>>0,Number(le)>>>0)):[],outputShape:me?Array.from(M().subarray(Number(me)>>>0,Number(Ie)>>>0)):[],activation:xe(Rt)})},847465:(o,p,h,y,v,I,B,D,W,K,se,le,me,Ie)=>{i.kb("ConvTranspose",o,{format:D?"NHWC":"NCHW",autoPad:p,dilations:Array.from(M().subarray(Number(h)>>>0,2+(Number(h)>>>0)>>>0)),group:y,kernelShape:Array.from(M().subarray(Number(v)>>>0,2+(Number(v)>>>0)>>>0)),pads:Array.from(M().subarray(Number(I)>>>0,4+(Number(I)>>>0)>>>0)),strides:Array.from(M().subarray(Number(B)>>>0,2+(Number(B)>>>0)>>>0)),wIsConst:()=>!!U()[W>>>0],outputPadding:K?Array.from(M().subarray(Number(K)>>>0,Number(se)>>>0)):[],outputShape:le?Array.from(M().subarray(Number(le)>>>0,Number(me)>>>0)):[],activation:xe(Ie)})},848126:(o,p)=>{i.kb("GlobalAveragePool",o,{format:p?"NHWC":"NCHW"})},848217:(o,p,h,y,v,I,B,D,W,K,se,le,me,Ie)=>{i.kb("AveragePool",o,{format:Ie?"NHWC":"NCHW",auto_pad:p,ceil_mode:h,count_include_pad:y,storage_order:v,dilations:I?Array.from(M().subarray(Number(I)>>>0,Number(B)>>>0)):[],kernel_shape:D?Array.from(M().subarray(Number(D)>>>0,Number(W)>>>0)):[],pads:K?Array.from(M().subarray(Number(K)>>>0,Number(se)>>>0)):[],strides:le?Array.from(M().subarray(Number(le)>>>0,Number(me)>>>0)):[]})},848696:(o,p)=>{i.kb("GlobalAveragePool",o,{format:p?"NHWC":"NCHW"})},848787:(o,p,h,y,v,I,B,D,W,K,se,le,me,Ie)=>{i.kb("AveragePool",o,{format:Ie?"NHWC":"NCHW",auto_pad:p,ceil_mode:h,count_include_pad:y,storage_order:v,dilations:I?Array.from(M().subarray(Number(I)>>>0,Number(B)>>>0)):[],kernel_shape:D?Array.from(M().subarray(Number(D)>>>0,Number(W)>>>0)):[],pads:K?Array.from(M().subarray(Number(K)>>>0,Number(se)>>>0)):[],strides:le?Array.from(M().subarray(Number(le)>>>0,Number(me)>>>0)):[]})},849266:(o,p)=>{i.kb("GlobalMaxPool",o,{format:p?"NHWC":"NCHW"})},849353:(o,p,h,y,v,I,B,D,W,K,se,le,me,Ie)=>{i.kb("MaxPool",o,{format:Ie?"NHWC":"NCHW",auto_pad:p,ceil_mode:h,count_include_pad:y,storage_order:v,dilations:I?Array.from(M().subarray(Number(I)>>>0,Number(B)>>>0)):[],kernel_shape:D?Array.from(M().subarray(Number(D)>>>0,Number(W)>>>0)):[],pads:K?Array.from(M().subarray(Number(K)>>>0,Number(se)>>>0)):[],strides:le?Array.from(M().subarray(Number(le)>>>0,Number(me)>>>0)):[]})},849828:(o,p)=>{i.kb("GlobalMaxPool",o,{format:p?"NHWC":"NCHW"})},849915:(o,p,h,y,v,I,B,D,W,K,se,le,me,Ie)=>{i.kb("MaxPool",o,{format:Ie?"NHWC":"NCHW",auto_pad:p,ceil_mode:h,count_include_pad:y,storage_order:v,dilations:I?Array.from(M().subarray(Number(I)>>>0,Number(B)>>>0)):[],kernel_shape:D?Array.from(M().subarray(Number(D)>>>0,Number(W)>>>0)):[],pads:K?Array.from(M().subarray(Number(K)>>>0,Number(se)>>>0)):[],strides:le?Array.from(M().subarray(Number(le)>>>0,Number(me)>>>0)):[]})},850390:(o,p,h,y,v)=>{i.kb("Gemm",o,{alpha:p,beta:h,transA:y,transB:v})},850494:o=>{i.kb("MatMul",o,void 0)},850548:(o,p,h,y)=>{i.kb("ArgMax",o,{keepDims:!!p,selectLastIndex:!!h,axis:y})},850656:(o,p,h,y)=>{i.kb("ArgMin",o,{keepDims:!!p,selectLastIndex:!!h,axis:y})},850764:(o,p)=>{i.kb("Softmax",o,{axis:p})},850827:(o,p)=>{i.kb("Concat",o,{axis:p})},850887:(o,p,h,y,v)=>{i.kb("Split",o,{axis:p,numOutputs:h,splitSizes:y?Array.from(M().subarray(Number(y)>>>0,Number(v)>>>0)):[]})},851043:o=>{i.kb("Expand",o,void 0)},851097:(o,p)=>{i.kb("Gather",o,{axis:Number(p)})},851168:(o,p)=>{i.kb("GatherElements",o,{axis:Number(p)})},851247:(o,p)=>{i.kb("GatherND",o,{batch_dims:Number(p)})},851326:(o,p,h,y,v,I,B,D,W,K,se)=>{i.kb("Resize",o,{antialias:p,axes:h?Array.from(M().subarray(Number(h)>>>0,Number(y)>>>0)):[],coordinateTransformMode:xe(v),cubicCoeffA:I,excludeOutside:B,extrapolationValue:D,keepAspectRatioPolicy:xe(W),mode:xe(K),nearestMode:xe(se)})},851688:(o,p,h,y,v,I,B)=>{i.kb("Slice",o,{starts:p?Array.from(M().subarray(Number(p)>>>0,Number(h)>>>0)):[],ends:y?Array.from(M().subarray(Number(y)>>>0,Number(v)>>>0)):[],axes:I?Array.from(M().subarray(Number(I)>>>0,Number(B)>>>0)):[]})},851952:o=>{i.kb("Tile",o,void 0)},852004:(o,p,h)=>{i.kb("InstanceNormalization",o,{epsilon:p,format:h?"NHWC":"NCHW"})},852118:(o,p,h)=>{i.kb("InstanceNormalization",o,{epsilon:p,format:h?"NHWC":"NCHW"})},852232:o=>{i.kb("Range",o,void 0)},852285:(o,p)=>{i.kb("Einsum",o,{equation:xe(p)})},852366:(o,p,h,y,v)=>{i.kb("Pad",o,{mode:p,value:h,pads:y?Array.from(M().subarray(Number(y)>>>0,Number(v)>>>0)):[]})},852509:(o,p,h,y,v,I)=>{i.kb("BatchNormalization",o,{epsilon:p,momentum:h,spatial:!!v,trainingMode:!!y,format:I?"NHWC":"NCHW"})},852678:(o,p,h,y,v,I)=>{i.kb("BatchNormalization",o,{epsilon:p,momentum:h,spatial:!!v,trainingMode:!!y,format:I?"NHWC":"NCHW"})},852847:(o,p,h)=>{i.kb("CumSum",o,{exclusive:Number(p),reverse:Number(h)})},852944:(o,p,h)=>{i.kb("DequantizeLinear",o,{axis:p,blockSize:h})},853034:(o,p,h,y,v)=>{i.kb("GridSample",o,{align_corners:p,mode:xe(h),padding_mode:xe(y),format:v?"NHWC":"NCHW"})},853204:(o,p,h,y,v)=>{i.kb("GridSample",o,{align_corners:p,mode:xe(h),padding_mode:xe(y),format:v?"NHWC":"NCHW"})},853374:(o,p)=>{i.kb("ScatterND",o,{reduction:xe(p)})},853459:(o,p,h,y,v,I,B,D,W)=>{i.kb("Attention",o,{numHeads:p,isUnidirectional:h,maskFilterValue:y,scale:v,doRotary:I,qkvHiddenSizes:B?Array.from(M().subarray(Number(D)>>>0,Number(D)+B>>>0)):[],pastPresentShareBuffer:!!W})},853731:o=>{i.kb("BiasAdd",o,void 0)},853786:o=>{i.kb("BiasSplitGelu",o,void 0)},853847:o=>{i.kb("FastGelu",o,void 0)},853903:(o,p,h,y,v,I,B,D,W,K,se,le,me,Ie,Rt,em)=>{i.kb("Conv",o,{format:le?"NHWC":"NCHW",auto_pad:p,dilations:h?Array.from(M().subarray(Number(h)>>>0,Number(y)>>>0)):[],group:v,kernel_shape:I?Array.from(M().subarray(Number(I)>>>0,Number(B)>>>0)):[],pads:D?Array.from(M().subarray(Number(D)>>>0,Number(W)>>>0)):[],strides:K?Array.from(M().subarray(Number(K)>>>0,Number(se)>>>0)):[],w_is_const:()=>!!U()[Number(me)>>>0],activation:xe(Ie),activation_params:Rt?Array.from(At().subarray(Number(Rt)>>>0,Number(em)>>>0)):[]})},854487:o=>{i.kb("Gelu",o,void 0)},854539:(o,p,h,y,v,I,B,D,W)=>{i.kb("GroupQueryAttention",o,{numHeads:p,kvNumHeads:h,scale:y,softcap:v,doRotary:I,rotaryInterleaved:B,smoothSoftmax:D,localWindowSize:W})},854756:(o,p,h,y)=>{i.kb("LayerNormalization",o,{axis:p,epsilon:h,simplified:!!y})},854867:(o,p,h,y)=>{i.kb("LayerNormalization",o,{axis:p,epsilon:h,simplified:!!y})},854978:(o,p,h,y,v,I)=>{i.kb("MatMulNBits",o,{k:p,n:h,accuracyLevel:y,bits:v,blockSize:I})},855105:(o,p,h,y,v,I)=>{i.kb("MultiHeadAttention",o,{numHeads:p,isUnidirectional:h,maskFilterValue:y,scale:v,doRotary:I})},855264:(o,p)=>{i.kb("QuickGelu",o,{alpha:p})},855328:(o,p,h,y,v)=>{i.kb("RotaryEmbedding",o,{interleaved:!!p,numHeads:h,rotaryEmbeddingDim:y,scale:v})},855467:(o,p,h)=>{i.kb("SkipLayerNormalization",o,{epsilon:p,simplified:!!h})},855569:(o,p,h)=>{i.kb("SkipLayerNormalization",o,{epsilon:p,simplified:!!h})},855671:(o,p,h,y)=>{i.kb("GatherBlockQuantized",o,{gatherAxis:p,quantizeAxis:h,blockSize:y})},855792:o=>{i.$b(o)},855826:(o,p)=>i.bc(Number(o),Number(p),i.Gb.ec,i.Gb.errors)};function Nf(o,p,h){return Un(async()=>{await i.Yb(Number(o),Number(p),Number(h))})}function Mf(){return typeof wasmOffsetConverter<"u"}class Hr{constructor(p){ys(this,"name","ExitStatus");this.message=`Program terminated with exit(${p})`,this.status=p}}var sn=o=>{o.terminate(),o.onmessage=()=>{}},Fr=[],on=o=>{ut.length==0&&(fn(),cn(ut[0]));var p=ut.pop();if(!p)return 6;Wt.push(p),bt[o.Bb]=p,p.Bb=o.Bb;var h={Cb:"run",hc:o.fc,Ib:o.Ib,Bb:o.Bb};return p.postMessage(h,o.Nb),0},ot=0,be=(o,p,...h)=>{for(var y=2*h.length,v=di(),I=li(8*y),B=I>>>3,D=0;D<h.length;D++){var W=h[D];typeof W=="bigint"?(L[B+2*D]=1n,L[B+2*D+1]=W):(L[B+2*D]=0n,ze()[B+2*D+1>>>0]=W)}return o=os(o,0,y,I,p),br(v),o};function jr(o){if(l)return be(0,1,o);if(C=o,!(0<ot)){for(var p of Wt)sn(p);for(p of ut)sn(p);ut=[],Wt=[],bt={},ye=!0}x(0,new Hr(o))}function un(o){if(l)return be(1,0,o);Kr(o)}var Kr=o=>{if(C=o,l)throw un(o),"unwind";jr(o)},ut=[],Wt=[],ln=[],bt={},dn=o=>{var p=o.Bb;delete bt[p],ut.push(o),Wt.splice(Wt.indexOf(o),1),o.Bb=0,us(p)};function pn(){ln.forEach(o=>o())}var cn=o=>new Promise(p=>{o.onmessage=v=>{var I=(v=v.data).Cb;if(v.Hb&&v.Hb!=_r()){var B=bt[v.Hb];B?B.postMessage(v,v.Nb):T(`Internal error! Worker sent a message "${I}" to target pthread ${v.Hb}, but that thread no longer exists!`)}else I==="checkMailbox"?lr():I==="spawnThread"?on(v):I==="cleanupThread"?dn(bt[v.ic]):I==="loaded"?(o.loaded=!0,p(o)):I==="alert"?alert(`Thread ${v.jc}: ${v.text}`):v.target==="setimmediate"?o.postMessage(v):I==="callHandler"?i[v.Rb](...v.args):I&&T(`worker sent an unknown command ${I}`)},o.onerror=v=>{throw T(`worker sent an error! ${v.filename}:${v.lineno}: ${v.message}`),v};var h,y=[];for(h of[])i.propertyIsEnumerable(h)&&y.push(h);o.postMessage({Cb:"load",Sb:y,lc:E,mc:z})});function fn(){var o=new Worker((()=>{let p=URL;return import.meta.url>"file:"&&import.meta.url<"file;"?new p("ort.bundle.min.mjs",import.meta.url):new URL(import.meta.url)})(),{type:"module",workerData:"em-pthread",name:"em-pthread"});ut.push(o)}var Df=o=>{fe();var p=ce()[o+52>>>2>>>0];o=ce()[o+56>>>2>>>0],ps(p,p-o),br(p)},Pf=(o,p)=>{ot=0,o=cs(o,p),0<ot?C=o:ui(o)};class Uf{constructor(p){this.Jb=p-24}}function qf(o,p,h){var y=new Uf(o>>>=0);throw p>>>=0,h>>>=0,ce()[y.Jb+16>>>2>>>0]=0,ce()[y.Jb+4>>>2>>>0]=p,ce()[y.Jb+8>>>2>>>0]=h,o}function hn(o,p,h,y){return l?be(2,1,o,p,h,y):mn(o,p,h,y)}function mn(o,p,h,y){if(o>>>=0,h>>>=0,y>>>=0,c===void 0)return 6;var v=[];return l&&v.length===0?hn(o,p>>>=0,h,y):(o={fc:h,Bb:o,Ib:y,Nb:v},l?(o.Cb="spawnThread",postMessage(o,v),0):on(o))}var gn=typeof TextDecoder<"u"?new TextDecoder:void 0,_n=(o,p=0,h=NaN)=>{var y=(p>>>=0)+h;for(h=p;o[h]&&!(h>=y);)++h;if(16<h-p&&o.buffer&&gn)return gn.decode(o.buffer instanceof ArrayBuffer?o.subarray(p,h):o.slice(p,h));for(y="";p<h;){var v=o[p++];if(128&v){var I=63&o[p++];if((224&v)==192)y+=String.fromCharCode((31&v)<<6|I);else{var B=63&o[p++];65536>(v=(240&v)==224?(15&v)<<12|I<<6|B:(7&v)<<18|I<<12|B<<6|63&o[p++])?y+=String.fromCharCode(v):(v-=65536,y+=String.fromCharCode(55296|v>>10,56320|1023&v))}}else y+=String.fromCharCode(v)}return y},xe=(o,p)=>(o>>>=0)?_n(V(),o,p):"";function yn(o,p,h){return l?be(3,1,o,p,h):0}function bn(o,p){if(l)return be(4,1,o,p)}var wn=o=>{for(var p=0,h=0;h<o.length;++h){var y=o.charCodeAt(h);127>=y?p++:2047>=y?p+=2:55296<=y&&57343>=y?(p+=4,++h):p+=3}return p},Bt=(o,p,h)=>{var y=V();if(p>>>=0,0<h){var v=p;h=p+h-1;for(var I=0;I<o.length;++I){var B=o.charCodeAt(I);if(55296<=B&&57343>=B&&(B=65536+((1023&B)<<10)|1023&o.charCodeAt(++I)),127>=B){if(p>=h)break;y[p++>>>0]=B}else{if(2047>=B){if(p+1>=h)break;y[p++>>>0]=192|B>>6}else{if(65535>=B){if(p+2>=h)break;y[p++>>>0]=224|B>>12}else{if(p+3>=h)break;y[p++>>>0]=240|B>>18,y[p++>>>0]=128|B>>12&63}y[p++>>>0]=128|B>>6&63}y[p++>>>0]=128|63&B}}y[p>>>0]=0,o=p-v}else o=0;return o};function $n(o,p){if(l)return be(5,1,o,p)}function vn(o,p,h){if(l)return be(6,1,o,p,h)}function xn(o,p,h){return l?be(7,1,o,p,h):0}function kn(o,p){if(l)return be(8,1,o,p)}function Sn(o,p,h){if(l)return be(9,1,o,p,h)}function Tn(o,p,h,y){if(l)return be(10,1,o,p,h,y)}function In(o,p,h,y){if(l)return be(11,1,o,p,h,y)}function En(o,p,h,y){if(l)return be(12,1,o,p,h,y)}function zn(o){if(l)return be(13,1,o)}function Cn(o,p){if(l)return be(14,1,o,p)}function On(o,p,h){if(l)return be(15,1,o,p,h)}var An,lt,Wf=()=>st(""),Ke=o=>{for(var p="";V()[o>>>0];)p+=An[V()[o++>>>0]];return p},Zr={},Qr={};function tt(o,p,h={}){return function(y,v,I={}){var B=v.name;if(!y)throw new lt(`type "${B}" must have a positive integer typeid pointer`);if(Qr.hasOwnProperty(y)){if(I.Tb)return;throw new lt(`Cannot register type '${B}' twice`)}Qr[y]=v,Zr.hasOwnProperty(y)&&(v=Zr[y],delete Zr[y],v.forEach(D=>D()))}(o,p,h)}var Bn=(o,p,h)=>{switch(p){case 1:return h?y=>U()[y>>>0]:y=>V()[y>>>0];case 2:return h?y=>te()[y>>>1>>>0]:y=>Te()[y>>>1>>>0];case 4:return h?y=>M()[y>>>2>>>0]:y=>ce()[y>>>2>>>0];case 8:return h?y=>L[y>>>3]:y=>ie[y>>>3];default:throw new TypeError(`invalid integer width (${p}): ${o}`)}};function Vf(o,p,h){h>>>=0,tt(o>>>=0,{name:p=Ke(p>>>0),fromWireType:y=>y,toWireType:function(y,v){if(typeof v!="bigint"&&typeof v!="number")throw v=v===null?"null":(y=typeof v)=="object"||y==="array"||y==="function"?v.toString():""+v,new TypeError(`Cannot convert "${v}" to ${this.name}`);return typeof v=="number"&&(v=BigInt(v)),v},Db:dt,readValueFromPointer:Bn(p,h,p.indexOf("u")==-1),Eb:null})}var dt=8;function Lf(o,p,h,y){tt(o>>>=0,{name:p=Ke(p>>>0),fromWireType:function(v){return!!v},toWireType:function(v,I){return I?h:y},Db:dt,readValueFromPointer:function(v){return this.fromWireType(V()[v>>>0])},Eb:null})}var Xr=[],rt=[];function Yr(o){9<(o>>>=0)&&--rt[o+1]==0&&(rt[o]=void 0,Xr.push(o))}var Ce=o=>{if(!o)throw new lt("Cannot use deleted val. handle = "+o);return rt[o]},De=o=>{switch(o){case void 0:return 2;case null:return 4;case!0:return 6;case!1:return 8;default:let p=Xr.pop()||rt.length;return rt[p]=o,rt[p+1]=1,p}};function Jr(o){return this.fromWireType(ce()[o>>>2>>>0])}var Gf={name:"emscripten::val",fromWireType:o=>{var p=Ce(o);return Yr(o),p},toWireType:(o,p)=>De(p),Db:dt,readValueFromPointer:Jr,Eb:null};function Hf(o){return tt(o>>>0,Gf)}var Ff=(o,p)=>{switch(p){case 4:return function(h){return this.fromWireType(At()[h>>>2>>>0])};case 8:return function(h){return this.fromWireType(ze()[h>>>3>>>0])};default:throw new TypeError(`invalid float width (${p}): ${o}`)}};function jf(o,p,h){h>>>=0,tt(o>>>=0,{name:p=Ke(p>>>0),fromWireType:y=>y,toWireType:(y,v)=>v,Db:dt,readValueFromPointer:Ff(p,h),Eb:null})}function Kf(o,p,h,y,v){if(o>>>=0,h>>>=0,p=Ke(p>>>0),v===-1&&(v=4294967295),v=D=>D,y===0){var I=32-8*h;v=D=>D<<I>>>I}var B=p.includes("unsigned")?function(D,W){return W>>>0}:function(D,W){return W};tt(o,{name:p,fromWireType:v,toWireType:B,Db:dt,readValueFromPointer:Bn(p,h,y!==0),Eb:null})}function Zf(o,p,h){function y(I){var B=ce()[I>>>2>>>0];return I=ce()[I+4>>>2>>>0],new v(U().buffer,I,B)}var v=[Int8Array,Uint8Array,Int16Array,Uint16Array,Int32Array,Uint32Array,Float32Array,Float64Array,BigInt64Array,BigUint64Array][p];tt(o>>>=0,{name:h=Ke(h>>>0),fromWireType:y,Db:dt,readValueFromPointer:y},{Tb:!0})}function Qf(o,p){tt(o>>>=0,{name:p=Ke(p>>>0),fromWireType:function(h){for(var y,v=ce()[h>>>2>>>0],I=h+4,B=I,D=0;D<=v;++D){var W=I+D;D!=v&&V()[W>>>0]!=0||(B=xe(B,W-B),y===void 0?y=B:(y+="\0",y+=B),B=W+1)}return Qe(h),y},toWireType:function(h,y){y instanceof ArrayBuffer&&(y=new Uint8Array(y));var v=typeof y=="string";if(!(v||y instanceof Uint8Array||y instanceof Uint8ClampedArray||y instanceof Int8Array))throw new lt("Cannot pass non-string to std::string");var I=v?wn(y):y.length,B=yr(4+I+1),D=B+4;if(ce()[B>>>2>>>0]=I,v)Bt(y,D,I+1);else if(v)for(v=0;v<I;++v){var W=y.charCodeAt(v);if(255<W)throw Qe(B),new lt("String has UTF-16 code units that do not fit in 8 bits");V()[D+v>>>0]=W}else for(v=0;v<I;++v)V()[D+v>>>0]=y[v];return h!==null&&h.push(Qe,B),B},Db:dt,readValueFromPointer:Jr,Eb(h){Qe(h)}})}var Rn=typeof TextDecoder<"u"?new TextDecoder("utf-16le"):void 0,Xf=(o,p)=>{for(var h=o>>1,y=h+p/2;!(h>=y)&&Te()[h>>>0];)++h;if(32<(h<<=1)-o&&Rn)return Rn.decode(V().slice(o,h));for(h="",y=0;!(y>=p/2);++y){var v=te()[o+2*y>>>1>>>0];if(v==0)break;h+=String.fromCharCode(v)}return h},Yf=(o,p,h)=>{if(h??(h=2147483647),2>h)return 0;var y=p;h=(h-=2)<2*o.length?h/2:o.length;for(var v=0;v<h;++v){var I=o.charCodeAt(v);te()[p>>>1>>>0]=I,p+=2}return te()[p>>>1>>>0]=0,p-y},Jf=o=>2*o.length,eh=(o,p)=>{for(var h=0,y="";!(h>=p/4);){var v=M()[o+4*h>>>2>>>0];if(v==0)break;++h,65536<=v?(v-=65536,y+=String.fromCharCode(55296|v>>10,56320|1023&v)):y+=String.fromCharCode(v)}return y},th=(o,p,h)=>{if(p>>>=0,h??(h=2147483647),4>h)return 0;var y=p;h=y+h-4;for(var v=0;v<o.length;++v){var I=o.charCodeAt(v);if(55296<=I&&57343>=I&&(I=65536+((1023&I)<<10)|1023&o.charCodeAt(++v)),M()[p>>>2>>>0]=I,(p+=4)+4>h)break}return M()[p>>>2>>>0]=0,p-y},rh=o=>{for(var p=0,h=0;h<o.length;++h){var y=o.charCodeAt(h);55296<=y&&57343>=y&&++h,p+=4}return p};function ih(o,p,h){if(o>>>=0,p>>>=0,h=Ke(h>>>=0),p===2)var y=Xf,v=Yf,I=Jf,B=D=>Te()[D>>>1>>>0];else p===4&&(y=eh,v=th,I=rh,B=D=>ce()[D>>>2>>>0]);tt(o,{name:h,fromWireType:D=>{for(var W,K=ce()[D>>>2>>>0],se=D+4,le=0;le<=K;++le){var me=D+4+le*p;le!=K&&B(me)!=0||(se=y(se,me-se),W===void 0?W=se:(W+="\0",W+=se),se=me+p)}return Qe(D),W},toWireType:(D,W)=>{if(typeof W!="string")throw new lt(`Cannot pass non-string to C++ string type ${h}`);var K=I(W),se=yr(4+K+p);return ce()[se>>>2>>>0]=K/p,v(W,se+4,K+p),D!==null&&D.push(Qe,se),se},Db:dt,readValueFromPointer:Jr,Eb(D){Qe(D)}})}function ah(o,p){tt(o>>>=0,{Ub:!0,name:p=Ke(p>>>0),Db:0,fromWireType:()=>{},toWireType:()=>{}})}function nh(o){oi(o>>>0,!d,1,!u,131072,!1),pn()}var ei=o=>{if(!ye)try{if(o(),!(0<ot))try{l?ui(C):Kr(C)}catch(p){p instanceof Hr||p=="unwind"||x(0,p)}}catch(p){p instanceof Hr||p=="unwind"||x(0,p)}};function ti(o){o>>>=0,typeof Atomics.kc=="function"&&(Atomics.kc(M(),o>>>2,o).value.then(lr),o+=128,Atomics.store(M(),o>>>2,1))}var lr=()=>{var o=_r();o&&(ti(o),ei(ds))};function sh(o,p){(o>>>=0)==p>>>0?setTimeout(lr):l?postMessage({Hb:o,Cb:"checkMailbox"}):(o=bt[o])&&o.postMessage({Cb:"checkMailbox"})}var ri=[];function oh(o,p,h,y,v){for(p>>>=0,y/=2,ri.length=y,h=v>>>0>>>3,v=0;v<y;v++)ri[v]=L[h+2*v]?L[h+2*v+1]:ze()[h+2*v+1>>>0];return(p?Gr[p]:Jh[o])(...ri)}var uh=()=>{ot=0};function lh(o){o>>>=0,l?postMessage({Cb:"cleanupThread",ic:o}):dn(bt[o])}function dh(o){}var dr=(o,p)=>{var h=Qr[o];if(h===void 0)throw o=as(o),h=Ke(o),Qe(o),new lt(`${p} has unknown type ${h}`);return h},Nn=(o,p,h)=>{var y=[];return o=o.toWireType(y,h),y.length&&(ce()[p>>>2>>>0]=De(y)),o};function ph(o,p,h){return p>>>=0,h>>>=0,o=Ce(o>>>0),p=dr(p,"emval::as"),Nn(p,h,o)}function ch(o,p){return p>>>=0,o=Ce(o>>>0),(p=dr(p,"emval::as")).toWireType(null,o)}var pr=o=>{try{o()}catch(p){st(p)}},pt=0,Ze=null,Mn=0,cr=[],Dn={},Pn={},fh=0,ii=null,hh=[];function Un(o){return function(p){if(!ye){if(pt===0){var h=!1,y=!1;p((v=0)=>{if(!ye&&(Mn=v,h=!0,y)){pt=2,pr(()=>ms(Ze)),typeof MainLoop<"u"&&MainLoop.Qb&&MainLoop.resume(),v=!1;try{var I=function(){var W=M()[Ze+8>>>2>>>0];return W=J[Pn[W]],--ot,W()}()}catch(W){I=W,v=!0}var B=!1;if(!Ze){var D=ii;D&&(ii=null,(v?D.reject:D.resolve)(I),B=!0)}if(v&&!B)throw I}}),y=!0,h||(pt=1,Ze=function(){var v=yr(65548),I=v+12;ce()[v>>>2>>>0]=I,ce()[v+4>>>2>>>0]=I+65536,I=cr[0];var B=Dn[I];return B===void 0&&(B=fh++,Dn[I]=B,Pn[B]=I),I=B,M()[v+8>>>2>>>0]=I,v}(),typeof MainLoop<"u"&&MainLoop.Qb&&MainLoop.pause(),pr(()=>fs(Ze)))}else pt===2?(pt=0,pr(gs),Qe(Ze),Ze=null,hh.forEach(ei)):st(`invalid state: ${pt}`);return Mn}}(p=>{o().then(p)})}function mh(o){return o>>>=0,Un(async()=>{var p=await Ce(o);return De(p)})}var fr=[];function gh(o,p,h,y){return h>>>=0,y>>>=0,(o=fr[o>>>0])(null,p=Ce(p>>>0),h,y)}var _h={},hr=o=>{var p=_h[o];return p===void 0?Ke(o):p};function yh(o,p,h,y,v){return h>>>=0,y>>>=0,v>>>=0,(o=fr[o>>>0])(p=Ce(p>>>0),p[h=hr(h)],y,v)}function bh(o,p){return p>>>=0,(o=Ce(o>>>0))==Ce(p)}var qn=()=>typeof globalThis=="object"?globalThis:Function("return this")();function wh(o){return(o>>>=0)==0?De(qn()):(o=hr(o),De(qn()[o]))}var $h=o=>{var p=fr.length;return fr.push(o),p},vh=(o,p)=>{for(var h=Array(o),y=0;y<o;++y)h[y]=dr(ce()[p+4*y>>>2>>>0],"parameter "+y);return h},Wn=(o,p)=>Object.defineProperty(p,"name",{value:o});function xh(o,p,h){var y=(p=vh(o,p>>>0)).shift();o--;var v=`return function (obj, func, destructorsRef, args) {
`,I=0,B=[];h===0&&B.push("obj");for(var D=["retType"],W=[y],K=0;K<o;++K)B.push("arg"+K),D.push("argType"+K),W.push(p[K]),v+=`  var arg${K} = argType${K}.readValueFromPointer(args${I?"+"+I:""});
`,I+=p[K].Db;return v+=`  var rv = ${h===1?"new func":"func.call"}(${B.join(", ")});
`,y.Ub||(D.push("emval_returnValue"),W.push(Nn),v+=`  return emval_returnValue(retType, destructorsRef, rv);
`),D.push(v+`};
`),o=function(se){var le=Function;if(!(le instanceof Function))throw new TypeError(`new_ called with constructor type ${typeof le} which is not a function`);var me=Wn(le.name||"unknownFunctionName",function(){});return me.prototype=le.prototype,me=new me,(se=le.apply(me,se))instanceof Object?se:me}(D)(...W),h=`methodCaller<(${p.map(se=>se.name).join(", ")}) => ${y.name}>`,$h(Wn(h,o))}function kh(o){return o=hr(o>>>0),De(i[o])}function Sh(o,p){return p>>>=0,o=Ce(o>>>0),p=Ce(p),De(o[p])}function Th(o){9<(o>>>=0)&&(rt[o+1]+=1)}function Ih(){return De([])}function Eh(o){o=Ce(o>>>0);for(var p=Array(o.length),h=0;h<o.length;h++)p[h]=o[h];return De(p)}function zh(o){return De(hr(o>>>0))}function Ch(){return De({})}function Oh(o){for(var p=Ce(o>>>=0);p.length;){var h=p.pop();p.pop()(h)}Yr(o)}function Ah(o,p,h){p>>>=0,h>>>=0,o=Ce(o>>>0),p=Ce(p),h=Ce(h),o[p]=h}function Bh(o,p){return p>>>=0,o=(o=dr(o>>>0,"_emval_take_value")).readValueFromPointer(p),De(o)}function Rh(o,p){o=-9007199254740992>o||9007199254740992<o?NaN:Number(o),p>>>=0,o=new Date(1e3*o),M()[p>>>2>>>0]=o.getUTCSeconds(),M()[p+4>>>2>>>0]=o.getUTCMinutes(),M()[p+8>>>2>>>0]=o.getUTCHours(),M()[p+12>>>2>>>0]=o.getUTCDate(),M()[p+16>>>2>>>0]=o.getUTCMonth(),M()[p+20>>>2>>>0]=o.getUTCFullYear()-1900,M()[p+24>>>2>>>0]=o.getUTCDay(),o=(o.getTime()-Date.UTC(o.getUTCFullYear(),0,1,0,0,0,0))/864e5|0,M()[p+28>>>2>>>0]=o}var Vn=o=>o%4==0&&(o%100!=0||o%400==0),Ln=[0,31,60,91,121,152,182,213,244,274,305,335],Gn=[0,31,59,90,120,151,181,212,243,273,304,334];function Nh(o,p){o=-9007199254740992>o||9007199254740992<o?NaN:Number(o),p>>>=0,o=new Date(1e3*o),M()[p>>>2>>>0]=o.getSeconds(),M()[p+4>>>2>>>0]=o.getMinutes(),M()[p+8>>>2>>>0]=o.getHours(),M()[p+12>>>2>>>0]=o.getDate(),M()[p+16>>>2>>>0]=o.getMonth(),M()[p+20>>>2>>>0]=o.getFullYear()-1900,M()[p+24>>>2>>>0]=o.getDay();var h=(Vn(o.getFullYear())?Ln:Gn)[o.getMonth()]+o.getDate()-1|0;M()[p+28>>>2>>>0]=h,M()[p+36>>>2>>>0]=-60*o.getTimezoneOffset(),h=new Date(o.getFullYear(),6,1).getTimezoneOffset();var y=new Date(o.getFullYear(),0,1).getTimezoneOffset();o=0|(h!=y&&o.getTimezoneOffset()==Math.min(y,h)),M()[p+32>>>2>>>0]=o}function Mh(o){o>>>=0;var p=new Date(M()[o+20>>>2>>>0]+1900,M()[o+16>>>2>>>0],M()[o+12>>>2>>>0],M()[o+8>>>2>>>0],M()[o+4>>>2>>>0],M()[o>>>2>>>0],0),h=M()[o+32>>>2>>>0],y=p.getTimezoneOffset(),v=new Date(p.getFullYear(),6,1).getTimezoneOffset(),I=new Date(p.getFullYear(),0,1).getTimezoneOffset(),B=Math.min(I,v);return 0>h?M()[o+32>>>2>>>0]=+(v!=I&&B==y):0<h!=(B==y)&&(v=Math.max(I,v),p.setTime(p.getTime()+6e4*((0<h?B:v)-y))),M()[o+24>>>2>>>0]=p.getDay(),h=(Vn(p.getFullYear())?Ln:Gn)[p.getMonth()]+p.getDate()-1|0,M()[o+28>>>2>>>0]=h,M()[o>>>2>>>0]=p.getSeconds(),M()[o+4>>>2>>>0]=p.getMinutes(),M()[o+8>>>2>>>0]=p.getHours(),M()[o+12>>>2>>>0]=p.getDate(),M()[o+16>>>2>>>0]=p.getMonth(),M()[o+20>>>2>>>0]=p.getYear(),o=p.getTime(),BigInt(isNaN(o)?-1:o/1e3)}function Hn(o,p,h,y,v,I,B){return l?be(16,1,o,p,h,y,v,I,B):-52}function Fn(o,p,h,y,v,I){if(l)return be(17,1,o,p,h,y,v,I)}var Vt={},Dh=()=>performance.timeOrigin+performance.now();function jn(o,p){if(l)return be(18,1,o,p);if(Vt[o]&&(clearTimeout(Vt[o].id),delete Vt[o]),!p)return 0;var h=setTimeout(()=>{delete Vt[o],ei(()=>ls(o,performance.timeOrigin+performance.now()))},p);return Vt[o]={id:h,rc:p},0}function Ph(o,p,h,y){o>>>=0,p>>>=0,h>>>=0,y>>>=0;var v=new Date().getFullYear(),I=new Date(v,0,1).getTimezoneOffset();v=new Date(v,6,1).getTimezoneOffset();var B=Math.max(I,v);ce()[o>>>2>>>0]=60*B,M()[p>>>2>>>0]=+(I!=v),o=(p=D=>{var W=Math.abs(D);return`UTC${0<=D?"-":"+"}${String(Math.floor(W/60)).padStart(2,"0")}${String(W%60).padStart(2,"0")}`})(I),p=p(v),v<I?(Bt(o,h,17),Bt(p,y,17)):(Bt(o,y,17),Bt(p,h,17))}var Uh=()=>Date.now();function qh(o,p,h){return 0<=o&&3>=o?(o===0?o=Date.now():o=performance.timeOrigin+performance.now(),L[h>>>0>>>3]=BigInt(Math.round(1e6*o)),0):28}var ai=[],Kn=(o,p)=>{ai.length=0;for(var h;h=V()[o++>>>0];){var y=h!=105;p+=(y&=h!=112)&&p%8?4:0,ai.push(h==112?ce()[p>>>2>>>0]:h==106?L[p>>>3]:h==105?M()[p>>>2>>>0]:ze()[p>>>3>>>0]),p+=y?8:4}return ai};function Wh(o,p,h){return o>>>=0,p=Kn(p>>>0,h>>>0),Gr[o](...p)}function Vh(o,p,h){return o>>>=0,p=Kn(p>>>0,h>>>0),Gr[o](...p)}var Lh=()=>{};function Gh(o,p){return T(xe(o>>>0,p>>>0))}var Hh=()=>{throw ot+=1,"unwind"};function Fh(){return 4294901760}var jh=()=>navigator.hardwareConcurrency;function Kh(){return st("Cannot use emscripten_pc_get_function without -sUSE_OFFSET_CONVERTER"),0}function Zh(o){o>>>=0;var p=V().length;if(o<=p||4294901760<o)return!1;for(var h=1;4>=h;h*=2){var y=p*(1+.2/h);y=Math.min(y,o+100663296);e:{y=(Math.min(4294901760,65536*Math.ceil(Math.max(o,y)/65536))-E.buffer.byteLength+65535)/65536|0;try{E.grow(y),fe();var v=1;break e}catch{}v=void 0}if(v)return!0}return!1}var mr=()=>(st("Cannot use convertFrameToPC (needed by __builtin_return_address) without -sUSE_OFFSET_CONVERTER"),0),Lt={},Zn=o=>{o.forEach(p=>{mr()})};function Qh(){var o=Error().stack.toString().split(`
`);return o[0]=="Error"&&o.shift(),Zn(o),Lt.Mb=mr(),Lt.dc=o,Lt.Mb}function Xh(o,p,h){if(o>>>=0,p>>>=0,Lt.Mb==o)var y=Lt.dc;else(y=Error().stack.toString().split(`
`))[0]=="Error"&&y.shift(),Zn(y);for(var v=3;y[v]&&mr()!=o;)++v;for(o=0;o<h&&y[o+v];++o)M()[p+4*o>>>2>>>0]=mr();return o}var ni,si={},Qn=()=>{if(!ni){var o,p={USER:"web_user",LOGNAME:"web_user",PATH:"/",PWD:"/",HOME:"/home/web_user",LANG:(typeof navigator=="object"&&navigator.languages&&navigator.languages[0]||"C").replace("-","_")+".UTF-8",_:"./this.program"};for(o in si)si[o]===void 0?delete p[o]:p[o]=si[o];var h=[];for(o in p)h.push(`${o}=${p[o]}`);ni=h}return ni};function Xn(o,p){if(l)return be(19,1,o,p);o>>>=0,p>>>=0;var h=0;return Qn().forEach((y,v)=>{var I=p+h;for(v=ce()[o+4*v>>>2>>>0]=I,I=0;I<y.length;++I)U()[v++>>>0]=y.charCodeAt(I);U()[v>>>0]=0,h+=y.length+1}),0}function Yn(o,p){if(l)return be(20,1,o,p);o>>>=0,p>>>=0;var h=Qn();ce()[o>>>2>>>0]=h.length;var y=0;return h.forEach(v=>y+=v.length+1),ce()[p>>>2>>>0]=y,0}function Jn(o){return l?be(21,1,o):52}function es(o,p,h,y){return l?be(22,1,o,p,h,y):52}function ts(o,p,h,y){return l?be(23,1,o,p,h,y):70}var Yh=[null,[],[]];function rs(o,p,h,y){if(l)return be(24,1,o,p,h,y);p>>>=0,h>>>=0,y>>>=0;for(var v=0,I=0;I<h;I++){var B=ce()[p>>>2>>>0],D=ce()[p+4>>>2>>>0];p+=8;for(var W=0;W<D;W++){var K=V()[B+W>>>0],se=Yh[o];K===0||K===10?((o===1?k:T)(_n(se)),se.length=0):se.push(K)}v+=D}return ce()[y>>>2>>>0]=v,0}l||function(){for(var o=i.numThreads-1;o--;)fn();Fr.unshift(()=>{_t++,function(p){l?p():Promise.all(ut.map(cn)).then(p)}(()=>an())})}();for(var is=Array(256),gr=0;256>gr;++gr)is[gr]=String.fromCharCode(gr);An=is,lt=i.BindingError=class extends Error{constructor(o){super(o),this.name="BindingError"}},i.InternalError=class extends Error{constructor(o){super(o),this.name="InternalError"}},rt.push(0,1,void 0,1,null,1,!0,1,!1,1),i.count_emval_handles=()=>rt.length/2-5-Xr.length;var J,Jh=[jr,un,hn,yn,bn,$n,vn,xn,kn,Sn,Tn,In,En,zn,Cn,On,Hn,Fn,jn,Xn,Yn,Jn,es,ts,rs];(async function(){function o(y,v){return J=y.exports,J=function(){var I=J,B={};for(let[D,W]of Object.entries(I))B[D]=typeof W=="function"?(...K)=>{cr.push(D);try{return W(...K)}finally{ye||(cr.pop(),Ze&&pt===1&&cr.length===0&&(pt=0,ot+=1,pr(hs),typeof Fibers<"u"&&Fibers.sc()))}}:W;return B}(),J=function(){var I=J,B=W=>K=>W(K)>>>0,D=W=>()=>W()>>>0;return(I=Object.assign({},I)).Ea=B(I.Ea),I.gb=D(I.gb),I.ib=B(I.ib),I.ub=B(I.ub),I.vb=D(I.vb),I.__cxa_get_exception_ptr=B(I.__cxa_get_exception_ptr),I}(),ln.push(J.jb),z=v,an(),J}_t++;var p=nn();if(i.instantiateWasm)return new Promise(y=>{i.instantiateWasm(p,(v,I)=>{o(v,I),y(v.exports)})});if(l)return new Promise(y=>{Ue=v=>{var I=new WebAssembly.Instance(v,nn());y(o(I,v))}});Be??(Be=i.locateFile?i.locateFile?i.locateFile("ort-wasm-simd-threaded.jsep.wasm",$):$+"ort-wasm-simd-threaded.jsep.wasm":new URL("/assets/ort-wasm-simd-threaded.jsep-CLPRrI3A.wasm",import.meta.url).href);try{var h=await async function(y){var v=Be;if(!Y&&typeof WebAssembly.instantiateStreaming=="function"&&!N(v))try{var I=fetch(v,{credentials:"same-origin"});return await WebAssembly.instantiateStreaming(I,y)}catch(B){T(`wasm streaming compile failed: ${B}`),T("falling back to ArrayBuffer instantiation")}return async function(B,D){try{var W=await async function(K){if(!Y)try{var se=await g(K);return new Uint8Array(se)}catch{}if(K==Be&&Y)K=new Uint8Array(Y);else{if(!_)throw"both async and sync fetching of the wasm failed";K=_(K)}return K}(B);return await WebAssembly.instantiate(W,D)}catch(K){T(`failed to asynchronously prepare wasm: ${K}`),st(K)}}(v,y)}(p);return o(h.instance,h.module)}catch(y){return n(y),Promise.reject(y)}})();var as=o=>(as=J.Ea)(o),ns=()=>(ns=J.Fa)();i._OrtInit=(o,p)=>(i._OrtInit=J.Ga)(o,p),i._OrtGetLastError=(o,p)=>(i._OrtGetLastError=J.Ha)(o,p),i._OrtCreateSessionOptions=(o,p,h,y,v,I,B,D,W,K)=>(i._OrtCreateSessionOptions=J.Ia)(o,p,h,y,v,I,B,D,W,K),i._OrtAppendExecutionProvider=(o,p,h,y,v)=>(i._OrtAppendExecutionProvider=J.Ja)(o,p,h,y,v),i._OrtAddFreeDimensionOverride=(o,p,h)=>(i._OrtAddFreeDimensionOverride=J.Ka)(o,p,h),i._OrtAddSessionConfigEntry=(o,p,h)=>(i._OrtAddSessionConfigEntry=J.La)(o,p,h),i._OrtReleaseSessionOptions=o=>(i._OrtReleaseSessionOptions=J.Ma)(o),i._OrtCreateSession=(o,p,h)=>(i._OrtCreateSession=J.Na)(o,p,h),i._OrtReleaseSession=o=>(i._OrtReleaseSession=J.Oa)(o),i._OrtGetInputOutputCount=(o,p,h)=>(i._OrtGetInputOutputCount=J.Pa)(o,p,h),i._OrtGetInputOutputMetadata=(o,p,h,y)=>(i._OrtGetInputOutputMetadata=J.Qa)(o,p,h,y),i._OrtFree=o=>(i._OrtFree=J.Ra)(o),i._OrtCreateTensor=(o,p,h,y,v,I)=>(i._OrtCreateTensor=J.Sa)(o,p,h,y,v,I),i._OrtGetTensorData=(o,p,h,y,v)=>(i._OrtGetTensorData=J.Ta)(o,p,h,y,v),i._OrtReleaseTensor=o=>(i._OrtReleaseTensor=J.Ua)(o),i._OrtCreateRunOptions=(o,p,h,y)=>(i._OrtCreateRunOptions=J.Va)(o,p,h,y),i._OrtAddRunConfigEntry=(o,p,h)=>(i._OrtAddRunConfigEntry=J.Wa)(o,p,h),i._OrtReleaseRunOptions=o=>(i._OrtReleaseRunOptions=J.Xa)(o),i._OrtCreateBinding=o=>(i._OrtCreateBinding=J.Ya)(o),i._OrtBindInput=(o,p,h)=>(i._OrtBindInput=J.Za)(o,p,h),i._OrtBindOutput=(o,p,h,y)=>(i._OrtBindOutput=J._a)(o,p,h,y),i._OrtClearBoundOutputs=o=>(i._OrtClearBoundOutputs=J.$a)(o),i._OrtReleaseBinding=o=>(i._OrtReleaseBinding=J.ab)(o),i._OrtRunWithBinding=(o,p,h,y,v)=>(i._OrtRunWithBinding=J.bb)(o,p,h,y,v),i._OrtRun=(o,p,h,y,v,I,B,D)=>(i._OrtRun=J.cb)(o,p,h,y,v,I,B,D),i._OrtEndProfiling=o=>(i._OrtEndProfiling=J.db)(o),i._JsepOutput=(o,p,h)=>(i._JsepOutput=J.eb)(o,p,h),i._JsepGetNodeName=o=>(i._JsepGetNodeName=J.fb)(o);var _r=()=>(_r=J.gb)(),Qe=i._free=o=>(Qe=i._free=J.hb)(o),yr=i._malloc=o=>(yr=i._malloc=J.ib)(o),oi=(o,p,h,y,v,I)=>(oi=J.lb)(o,p,h,y,v,I),ss=()=>(ss=J.mb)(),os=(o,p,h,y,v)=>(os=J.nb)(o,p,h,y,v),us=o=>(us=J.ob)(o),ui=o=>(ui=J.pb)(o),ls=(o,p)=>(ls=J.qb)(o,p),ds=()=>(ds=J.rb)(),ps=(o,p)=>(ps=J.sb)(o,p),br=o=>(br=J.tb)(o),li=o=>(li=J.ub)(o),di=()=>(di=J.vb)(),cs=i.dynCall_ii=(o,p)=>(cs=i.dynCall_ii=J.wb)(o,p),fs=o=>(fs=J.xb)(o),hs=()=>(hs=J.yb)(),ms=o=>(ms=J.zb)(o),gs=()=>(gs=J.Ab)();return i.stackSave=()=>di(),i.stackRestore=o=>br(o),i.stackAlloc=o=>li(o),i.setValue=function(o,p,h="i8"){switch(h.endsWith("*")&&(h="*"),h){case"i1":case"i8":U()[o>>>0]=p;break;case"i16":te()[o>>>1>>>0]=p;break;case"i32":M()[o>>>2>>>0]=p;break;case"i64":L[o>>>3]=BigInt(p);break;case"float":At()[o>>>2>>>0]=p;break;case"double":ze()[o>>>3>>>0]=p;break;case"*":ce()[o>>>2>>>0]=p;break;default:st(`invalid type for setValue: ${h}`)}},i.getValue=function(o,p="i8"){switch(p.endsWith("*")&&(p="*"),p){case"i1":case"i8":return U()[o>>>0];case"i16":return te()[o>>>1>>>0];case"i32":return M()[o>>>2>>>0];case"i64":return L[o>>>3];case"float":return At()[o>>>2>>>0];case"double":return ze()[o>>>3>>>0];case"*":return ce()[o>>>2>>>0];default:st(`invalid type for getValue: ${p}`)}},i.UTF8ToString=xe,i.stringToUTF8=Bt,i.lengthBytesUTF8=wn,function o(){if(0<_t)yt=o;else if(l)a(i),we();else{for(;0<Fr.length;)Fr.shift()(i);0<_t?yt=o:(i.calledRun=!0,ye||(we(),a(i)))}}(),i.PTR_SIZE=4,s}),bd=_i,ws=(t=(e=globalThis.self)==null?void 0:e.name)==null?void 0:t.startsWith("em-pthread"),ws&&_i()}),yi,ca,$s,Re,wd,$r,vs,xs,bi,ks,wi,$d,$i,vd,Aa=P(()=>{Oa(),yi=typeof location>"u"?void 0:location.origin,ca=import.meta.url>"file:"&&import.meta.url<"file;",$s=()=>{{if(ca){let e=URL;return new URL(new e("ort.bundle.min.mjs",import.meta.url).href,yi).href}return import.meta.url}},Re=$s(),wd=()=>{if(Re&&!Re.startsWith("blob:"))return Re.substring(0,Re.lastIndexOf("/")+1)},$r=(e,t)=>{try{let r=t??Re;return(r?new URL(e,r):new URL(e)).origin===yi}catch{return!1}},vs=(e,t)=>{let r=t??Re;try{return(r?new URL(e,r):new URL(e)).href}catch{return}},xs=(e,t)=>`${t??"./"}${e}`,bi=async e=>{let t=await(await fetch(e,{credentials:"same-origin"})).blob();return URL.createObjectURL(t)},ks=async e=>(await import(e)).default,wi=(vm(),or(gd)).default,$d=async()=>{if(!Re)throw new Error("Failed to load proxy worker: cannot determine the script source URL.");if($r(Re))return[void 0,wi()];let e=await bi(Re);return[e,wi(e)]},$i=(xm(),or(yd)).default,vd=async(e,t,r)=>{if(!e&&!t&&$i&&Re&&$r(Re))return[void 0,$i];{let a="ort-wasm-simd-threaded.jsep.mjs",n=e??vs(a,t),i=r&&n&&!$r(n,t),s=i?await bi(n):n??xs(a,t);return[i?s:void 0,await ks(s)]}}}),vi,vr,Ht,xi,Ss,Ts,Is,Ba,ge,Ct=P(()=>{Aa(),vr=!1,Ht=!1,xi=!1,Ss=()=>{if(typeof SharedArrayBuffer>"u")return!1;try{return typeof MessageChannel<"u"&&new MessageChannel().port1.postMessage(new SharedArrayBuffer(1)),WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0,1,4,1,96,0,0,3,2,1,0,5,4,1,3,1,1,10,11,1,9,0,65,0,254,16,2,0,26,11]))}catch{return!1}},Ts=()=>{try{return WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0,1,4,1,96,0,0,3,2,1,0,10,30,1,28,0,65,0,253,15,253,12,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,253,186,1,26,11]))}catch{return!1}},Is=()=>{try{return WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,123,3,2,1,0,10,19,1,17,0,65,1,253,15,65,2,253,15,65,3,253,15,253,147,2,11]))}catch{return!1}},Ba=async e=>{if(vr)return Promise.resolve();if(Ht)throw new Error("multiple calls to 'initializeWebAssembly()' detected.");if(xi)throw new Error("previous call to 'initializeWebAssembly()' failed.");Ht=!0;let t=e.initTimeout,r=e.numThreads;if(e.simd!==!1){if(e.simd==="relaxed"){if(!Is())throw new Error("Relaxed WebAssembly SIMD is not supported in the current environment.")}else if(!Ts())throw new Error("WebAssembly SIMD is not supported in the current environment.")}let a=Ss();r>1&&!a&&(typeof self<"u"&&!self.crossOriginIsolated&&console.warn("env.wasm.numThreads is set to "+r+", but this will not work unless you enable crossOriginIsolated mode. See https://web.dev/cross-origin-isolation-guide/ for more info."),console.warn("WebAssembly multi-threading is not supported in the current environment. Falling back to single-threading."),e.numThreads=r=1);let n=e.wasmPaths,i=typeof n=="string"?n:void 0,s=n==null?void 0:n.mjs,u=(s==null?void 0:s.href)??s,d=n==null?void 0:n.wasm,l=(d==null?void 0:d.href)??d,c=e.wasmBinary,[f,m]=await vd(u,i,r>1),g=!1,_=[];if(t>0&&_.push(new Promise(b=>{setTimeout(()=>{g=!0,b()},t)})),_.push(new Promise((b,x)=>{let $={numThreads:r};if(c)$.wasmBinary=c;else if(l||i)$.locateFile=w=>l??i+w;else if(u&&u.indexOf("blob:")!==0)$.locateFile=w=>new URL(w,u).href;else if(f){let w=wd();w&&($.locateFile=S=>w+S)}m($).then(w=>{Ht=!1,vr=!0,vi=w,b(),f&&URL.revokeObjectURL(f)},w=>{Ht=!1,xi=!0,x(w)})})),await Promise.race(_),g)throw new Error(`WebAssembly backend initializing failed due to timeout: ${t}ms`)},ge=()=>{if(vr&&vi)return vi;throw new Error("WebAssembly is not initialized yet.")}}),He,Mr,he,Ra=P(()=>{Ct(),He=(e,t)=>{let r=ge(),a=r.lengthBytesUTF8(e)+1,n=r._malloc(a);return r.stringToUTF8(e,n,a),t.push(n),n},Mr=(e,t,r,a)=>{if(typeof e=="object"&&e!==null){if(r.has(e))throw new Error("Circular reference in options");r.add(e)}Object.entries(e).forEach(([n,i])=>{let s=t?t+n:n;if(typeof i=="object")Mr(i,s+".",r,a);else if(typeof i=="string"||typeof i=="number")a(s,i.toString());else if(typeof i=="boolean")a(s,i?"1":"0");else throw new Error(`Can't handle extra config type: ${typeof i}`)})},he=e=>{let t=ge(),r=t.stackSave();try{let a=t.PTR_SIZE,n=t.stackAlloc(2*a);t._OrtGetLastError(n,n+a);let i=Number(t.getValue(n,a===4?"i32":"i64")),s=t.getValue(n+a,"*"),u=s?t.UTF8ToString(s):"";throw new Error(`${e} ERROR_CODE: ${i}, ERROR_MESSAGE: ${u}`)}finally{t.stackRestore(r)}}}),xd,km=P(()=>{Ct(),Ra(),xd=e=>{let t=ge(),r=0,a=[],n=e||{};try{if((e==null?void 0:e.logSeverityLevel)===void 0)n.logSeverityLevel=2;else if(typeof e.logSeverityLevel!="number"||!Number.isInteger(e.logSeverityLevel)||e.logSeverityLevel<0||e.logSeverityLevel>4)throw new Error(`log serverity level is not valid: ${e.logSeverityLevel}`);if((e==null?void 0:e.logVerbosityLevel)===void 0)n.logVerbosityLevel=0;else if(typeof e.logVerbosityLevel!="number"||!Number.isInteger(e.logVerbosityLevel))throw new Error(`log verbosity level is not valid: ${e.logVerbosityLevel}`);(e==null?void 0:e.terminate)===void 0&&(n.terminate=!1);let i=0;return(e==null?void 0:e.tag)!==void 0&&(i=He(e.tag,a)),r=t._OrtCreateRunOptions(n.logSeverityLevel,n.logVerbosityLevel,!!n.terminate,i),r===0&&he("Can't create run options."),(e==null?void 0:e.extra)!==void 0&&Mr(e.extra,"",new WeakSet,(s,u)=>{let d=He(s,a),l=He(u,a);t._OrtAddRunConfigEntry(r,d,l)!==0&&he(`Can't set a run config entry: ${s} - ${u}.`)}),[r,a]}catch(i){throw r!==0&&t._OrtReleaseRunOptions(r),a.forEach(s=>t._free(s)),i}}}),Es,zs,Cs,Ft,Os,kd,Sm=P(()=>{Ct(),Ra(),Es=e=>{switch(e){case"disabled":return 0;case"basic":return 1;case"extended":return 2;case"all":return 99;default:throw new Error(`unsupported graph optimization level: ${e}`)}},zs=e=>{switch(e){case"sequential":return 0;case"parallel":return 1;default:throw new Error(`unsupported execution mode: ${e}`)}},Cs=e=>{e.extra||(e.extra={}),e.extra.session||(e.extra.session={});let t=e.extra.session;t.use_ort_model_bytes_directly||(t.use_ort_model_bytes_directly="1"),e.executionProviders&&e.executionProviders.some(r=>(typeof r=="string"?r:r.name)==="webgpu")&&(e.enableMemPattern=!1)},Ft=(e,t,r,a)=>{let n=He(t,a),i=He(r,a);ge()._OrtAddSessionConfigEntry(e,n,i)!==0&&he(`Can't set a session config entry: ${t} - ${r}.`)},Os=async(e,t,r)=>{for(let a of t){let n=typeof a=="string"?a:a.name,i=[];switch(n){case"webnn":if(n="WEBNN",typeof a!="string"){let c=a==null?void 0:a.deviceType;c&&Ft(e,"deviceType",c,r)}break;case"webgpu":if(n="JS",typeof a!="string"){let c=a;if(c!=null&&c.preferredLayout){if(c.preferredLayout!=="NCHW"&&c.preferredLayout!=="NHWC")throw new Error(`preferredLayout must be either 'NCHW' or 'NHWC': ${c.preferredLayout}`);Ft(e,"preferredLayout",c.preferredLayout,r)}}break;case"wasm":case"cpu":continue;default:throw new Error(`not supported execution provider: ${n}`)}let s=He(n,r),u=i.length,d=0,l=0;if(u>0){d=ge()._malloc(u*ge().PTR_SIZE),r.push(d),l=ge()._malloc(u*ge().PTR_SIZE),r.push(l);for(let c=0;c<u;c++)ge().setValue(d+c*ge().PTR_SIZE,i[c][0],"*"),ge().setValue(l+c*ge().PTR_SIZE,i[c][1],"*")}await ge()._OrtAppendExecutionProvider(e,s,d,l,u)!==0&&he(`Can't append execution provider: ${n}.`)}},kd=async e=>{let t=ge(),r=0,a=[],n=e||{};Cs(n);try{let i=Es(n.graphOptimizationLevel??"all"),s=zs(n.executionMode??"sequential"),u=typeof n.logId=="string"?He(n.logId,a):0,d=n.logSeverityLevel??2;if(!Number.isInteger(d)||d<0||d>4)throw new Error(`log serverity level is not valid: ${d}`);let l=n.logVerbosityLevel??0;if(!Number.isInteger(l)||l<0||l>4)throw new Error(`log verbosity level is not valid: ${l}`);let c=typeof n.optimizedModelFilePath=="string"?He(n.optimizedModelFilePath,a):0;if(r=t._OrtCreateSessionOptions(i,!!n.enableCpuMemArena,!!n.enableMemPattern,s,!!n.enableProfiling,0,u,d,l,c),r===0&&he("Can't create session options."),n.executionProviders&&await Os(r,n.executionProviders,a),n.enableGraphCapture!==void 0){if(typeof n.enableGraphCapture!="boolean")throw new Error(`enableGraphCapture must be a boolean value: ${n.enableGraphCapture}`);Ft(r,"enableGraphCapture",n.enableGraphCapture.toString(),a)}if(n.freeDimensionOverrides)for(let[f,m]of Object.entries(n.freeDimensionOverrides)){if(typeof f!="string")throw new Error(`free dimension override name must be a string: ${f}`);if(typeof m!="number"||!Number.isInteger(m)||m<0)throw new Error(`free dimension override value must be a non-negative integer: ${m}`);let g=He(f,a);t._OrtAddFreeDimensionOverride(r,g,m)!==0&&he(`Can't set a free dimension override: ${f} - ${m}.`)}return n.extra!==void 0&&Mr(n.extra,"",new WeakSet,(f,m)=>{Ft(r,f,m,a)}),[r,a]}catch(i){throw r!==0&&t._OrtReleaseSessionOptions(r)!==0&&he("Can't release session options."),a.forEach(s=>t._free(s)),i}}}),St,at,Tt,Lr,Dr,Na,Ma,fa,ee=P(()=>{St=e=>{switch(e){case"int8":return 3;case"uint8":return 2;case"bool":return 9;case"int16":return 5;case"uint16":return 4;case"int32":return 6;case"uint32":return 12;case"float16":return 10;case"float32":return 1;case"float64":return 11;case"string":return 8;case"int64":return 7;case"uint64":return 13;case"int4":return 22;case"uint4":return 21;default:throw new Error(`unsupported data type: ${e}`)}},at=e=>{switch(e){case 3:return"int8";case 2:return"uint8";case 9:return"bool";case 5:return"int16";case 4:return"uint16";case 6:return"int32";case 12:return"uint32";case 10:return"float16";case 1:return"float32";case 11:return"float64";case 8:return"string";case 7:return"int64";case 13:return"uint64";case 22:return"int4";case 21:return"uint4";default:throw new Error(`unsupported data type: ${e}`)}},Tt=(e,t)=>{let r=[-1,4,1,1,2,2,4,8,-1,1,2,8,4,8,-1,-1,-1,-1,-1,-1,-1,.5,.5][e],a=typeof t=="number"?t:t.reduce((n,i)=>n*i,1);return r>0?Math.ceil(a*r):void 0},Lr=e=>{switch(e){case"float16":return typeof Float16Array<"u"&&Float16Array.from?Float16Array:Uint16Array;case"float32":return Float32Array;case"uint8":return Uint8Array;case"int8":return Int8Array;case"uint16":return Uint16Array;case"int16":return Int16Array;case"int32":return Int32Array;case"bool":return Uint8Array;case"float64":return Float64Array;case"uint32":return Uint32Array;case"int64":return BigInt64Array;case"uint64":return BigUint64Array;default:throw new Error(`unsupported type: ${e}`)}},Dr=e=>{switch(e){case"verbose":return 0;case"info":return 1;case"warning":return 2;case"error":return 3;case"fatal":return 4;default:throw new Error(`unsupported logging level: ${e}`)}},Na=e=>e==="float32"||e==="float16"||e==="int32"||e==="int64"||e==="uint32"||e==="uint8"||e==="bool"||e==="uint4"||e==="int4",Ma=e=>e==="float32"||e==="float16"||e==="int32"||e==="int64"||e==="uint32"||e==="uint64"||e==="int8"||e==="uint8"||e==="bool"||e==="uint4"||e==="int4",fa=e=>{switch(e){case"none":return 0;case"cpu":return 1;case"cpu-pinned":return 2;case"texture":return 3;case"gpu-buffer":return 4;case"ml-tensor":return 5;default:throw new Error(`unsupported data location: ${e}`)}}}),Da,Sd=P(()=>{Oa(),Da=async e=>{if(typeof e=="string"){let t=await fetch(e);if(!t.ok)throw new Error(`failed to load external data file: ${e}`);let r=t.headers.get("Content-Length"),a=r?parseInt(r,10):0;if(a<1073741824)return new Uint8Array(await t.arrayBuffer());{if(!t.body)throw new Error(`failed to load external data file: ${e}, no response body.`);let n=t.body.getReader(),i;try{i=new ArrayBuffer(a)}catch(u){if(u instanceof RangeError){let d=Math.ceil(a/65536);i=new WebAssembly.Memory({initial:d,maximum:d}).buffer}else throw u}let s=0;for(;;){let{done:u,value:d}=await n.read();if(u)break;let l=d.byteLength;new Uint8Array(i,s,l).set(d),s+=l}return new Uint8Array(i,0,a)}}else return e instanceof Blob?new Uint8Array(await e.arrayBuffer()):e instanceof Uint8Array?e:new Uint8Array(e)}}),As,Bs,Rs,Ns,Pa,Ms,ue,nt=P(()=>{ee(),As=["V","I","W","E","F"],Bs=(e,t)=>{console.log(`[${As[e]},${new Date().toISOString()}]${t}`)},Pa=(e,t)=>{Rs=e,Ns=t},Ms=(e,t)=>{let r=Dr(e),a=Dr(Rs);r>=a&&Bs(r,typeof t=="function"?t():t)},ue=(...e)=>{Ns&&Ms(...e)}}),Ds,Pt,O,Pr,Td,Id,Ed,ae=P(()=>{Ds=class{static calcMatMulShape(e,t){return e[1]!==t[0]?void 0:[e[0],t[1]]}},Pt=class{static calcShape(e,t,r=!1){let a=e.length,n=t.length;if(a===0)return t;if(n===0)return e;let i=Math.max(e.length,t.length),s=new Array(i);if(r){if(a<2||n<2)return;let u=Ds.calcMatMulShape([e[a-2],e[a-1]],[t[n-2],t[n-1]]);if(u===void 0)return;[s[i-2],s[i-1]]=u}for(let u=r?3:1;u<=i;u++){let d=a-u<0?1:e[a-u],l=n-u<0?1:t[n-u];if(d!==l&&d>1&&l>1)return;let c=Math.max(d,l);if(d&&l)s[i-u]=Math.max(d,l);else{if(c>1)return;s[i-u]=0}}return s}static isValidBroadcast(e,t){let r=e.length,a=t.length;if(r>a)return!1;for(let n=1;n<=r;n++)if(e[r-n]!==1&&e[r-n]!==t[a-n])return!1;return!0}},O=class Br{static size(t){return Br.getSizeFromDimensionRange(t,0,t.length)}static convertShape(t,r=4){let a=t.length;if(a===0)return[];let n=new Array(a),i=a-1;for(;i>=0;){if(t[i]%r===0){n[i]=t[i]/r;break}if(r%t[i]!==0)throw new Error("cannot convert shape");n[i]=1,r/=t[i],i--}for(i--;i>=0;i--)n[i]=t[i];return n}static sizeFromDimension(t,r){if(r<0||r>t.length)throw new Error(`invalid dimension of ${r} for sizeFromDimension as Tensor has ${t.length} dimensions.`);return Br.getSizeFromDimensionRange(t,r,t.length)}static sizeToDimension(t,r){if(r<0||r>t.length)throw new Error(`invalid dimension of ${r} for sizeToDimension as Tensor has ${t.length} dimensions.`);return Br.getSizeFromDimensionRange(t,0,r)}static getSizeFromDimensionRange(t,r,a){let n=1;for(let i=r;i<a;i++){if(t[i]<0)throw new Error("cannot get valid size from specified dimension range. Most likely the range contains negative values in them.");n*=Number(t[i])}return n}static computeStrides(t){let r=t.length;if(r===0)return[];if(r===1)return[1];let a=new Array(r);a[r-1]=1,a[r-2]=t[r-1];for(let n=r-3;n>=0;--n)a[n]=a[n+1]*t[n+1];return a}static normalizeAxis(t,r){if(t<-r&&t>=r)throw new Error("unsupported axis for this operation.");return t<0?t+r:t}static normalizeAxes(t,r){return t.map(a=>this.normalizeAxis(a,r??t.length))}static sortBasedOnPerm(t,r){return r?r.map(a=>t[a]):t.slice().reverse()}static padShape(t,r){let a=t.length;return t.map((n,i)=>n+r[i]+r[i+a])}static areEqual(t,r){return t.length!==r.length?!1:t.every((a,n)=>a===r[n])}},Pr=class rr{static adjustPoolAttributes(t,r,a,n,i,s){if(!t&&a.length!==r.length-2)throw new Error("length of specified kernel shapes should be 2 less than length of input dimensions");if(t)for(let u=0;u<r.length-2;u++)u>=a.length?a.push(r[u+2]):a[u]=r[u+2];for(let u=0;u<a.length;u++)if(u<n.length){if(n[u]<0)throw new Error("strides should be greater than or equal to 1")}else n.push(1);for(let u=0;u<a.length;u++)if(u<i.length){if(i[u]<0)throw new Error("dilations should be greater than or equal to 1")}else i.push(1);for(let u=0;u<a.length*2;u++)if(u<s.length){if(s[u]<0)throw new Error("pad should be greater than or equal to 1")}else s.push(0);for(let u=0;u<a.length;u++){if(a[u]<=0)throw new Error("kernel shapes need to be greater than 0");if(s[u]>=a[u]||s[u+a.length]>=a[u])throw new Error("pads should be smaller than kernel")}}static adjustPadsBasedOnAutoPad(t,r,a,n,i,s,u){if(u){if(i.length!==2*(t.length-2))throw new Error("length of pads should be twice the length of data dimensions");if(r.length!==t.length-2)throw new Error("length of strides should be the length of data dimensions");if(n.length!==t.length-2)throw new Error("length of kernel shapes should be the length of data dimensions");for(let d=0;d<t.length-2;d++)rr.adjustPadAndReturnShape(t[d+(s?1:2)],r[d],a[d],n[d],i,d,d+t.length-2,u)}}static computePoolOutputShape(t,r,a,n,i,s,u){if(r.length<=0)throw new Error("input shape must be of size greater than 0");let d=[r[0],r[1]];return rr.computeShapeHelper(t,r,d,a,n,i,s,u),d}static computeConvOutputShape(t,r,a,n,i,s,u){if(t.length<=0||r.length<=0)throw new Error("invalid input tensor dims or invalid filter tensor dims");let d=[t[0],r[0]];return rr.computeShapeHelper(!1,t,d,a,n,i,s,u),d}static computeShapeHelper(t,r,a,n,i,s,u,d){if(t)for(let l=0;l<r.length-2;l++)a.push(1);else for(let l=0;l<r.length-2;l++)a.push(rr.adjustPadAndReturnShape(r[l+2],n[l],i[l],s[l],u,l,l+r.length-2,d))}static adjustPadAndReturnShape(t,r,a,n,i,s,u,d){let l=a*(n-1)+1;if(d&&d!=="NOTSET")switch(d){case"VALID":return i[s]=0,i[u]=0,Math.floor((t-l)/r+1);case"SAME_LOWER":case"SAME_UPPER":if(a!==1)throw new Error("Dilation not supported for SAME_UPPER or SAME_LOWER");{let c=((t+r-1)/r-1)*r+n-t;return i[s]=Math.floor(d==="SAME_LOWER"?(c+1)/2:c/2),i[u]=c-i[s],Math.floor((t+c-n)/r+1)}default:throw new Error("Unsupported AutoPad type")}else return Math.floor((t+i[s]+i[u]-l)/r+1)}},Td=class{static getShapeOfGemmResult(e,t,r,a,n){if(e.length!==2||r.length!==2)throw new Error("shape need to be of size 2");let i,s,u;t?(i=e[1],s=e[0]):(i=e[0],s=e[1]);let d=-1;if(a?(u=r[0],d=1):(u=r[1],d=0),r[d]!==s)throw new Error("dimension mismatch");if(i<=0||u<=0||s<=0)throw new Error("invalid shape specified");if(n&&!Pt.isValidBroadcast(n,[i,u]))throw new Error("gemm: invalid bias shape for broadcast");return[i,u,s]}},Id=-34028234663852886e22,Ed=34028234663852886e22}),Ua,zd=P(()=>{ee(),Ua=(e,t)=>new(Lr(t))(e)}),ki,ha,Si,Ps,Ti,Us,Ii,Ei,zi,qs,Cd,Tm=P(()=>{ee(),nt(),ki=new Map([["float32",32],["float16",16],["int32",32],["uint32",32],["int64",64],["uint64",64],["int8",8],["uint8",8],["int4",4],["uint4",4]]),ha=(e,t)=>{if(t==="int32")return e;let r=ki.get(t);if(!r)throw new Error(`WebNN backend does not support data type: ${t}`);let a=r/8;if(e.byteLength%a!==0)throw new Error(`Invalid Uint8Array length - must be a multiple of ${a}.`);let n=e.byteLength/a,i=new(Lr(t))(e.buffer,e.byteOffset,n);switch(t){case"int64":case"uint64":{let s=new Int32Array(n);for(let u=0;u<n;u++){let d=i[u];if(d>2147483647n||d<-2147483648n)throw new Error("Can not convert int64 data to int32 - value out of range.");s[u]=Number(d)}return new Uint8Array(s.buffer)}case"int8":case"uint8":case"uint32":{if(t==="uint32"&&i.some(u=>u>2147483647))throw new Error("Can not convert uint32 data to int32 - value out of range.");let s=Int32Array.from(i,Number);return new Uint8Array(s.buffer)}default:throw new Error(`Unsupported data conversion from ${t} to 'int32'`)}},Si=(e,t)=>{if(t==="int32")return e;if(e.byteLength%4!==0)throw new Error("Invalid Uint8Array length - must be a multiple of 4 (int32).");let r=e.byteLength/4,a=new Int32Array(e.buffer,e.byteOffset,r);switch(t){case"int64":{let n=BigInt64Array.from(a,BigInt);return new Uint8Array(n.buffer)}case"uint64":{if(a.some(i=>i<0))throw new Error("Can not convert int32 data to uin64 - negative value found.");let n=BigUint64Array.from(a,BigInt);return new Uint8Array(n.buffer)}case"int8":{if(a.some(i=>i<-128||i>127))throw new Error("Can not convert int32 data to int8 - value out of range.");let n=Int8Array.from(a,Number);return new Uint8Array(n.buffer)}case"uint8":{if(a.some(n=>n<0||n>255))throw new Error("Can not convert int32 data to uint8 - value out of range.");return Uint8Array.from(a,Number)}case"uint32":{if(a.some(i=>i<0))throw new Error("Can not convert int32 data to uint32 - negative value found.");let n=Uint32Array.from(a,Number);return new Uint8Array(n.buffer)}default:throw new Error(`Unsupported data conversion from 'int32' to ${t}`)}},Ps=1,Ti=()=>Ps++,Us=new Map([["int8","int32"],["uint8","int32"],["uint32","int32"],["int64","int32"]]),Ii=(e,t)=>{let r=ki.get(e);if(!r)throw new Error(`WebNN backend does not support data type: ${e}`);return t.length>0?Math.ceil(t.reduce((a,n)=>a*n)*r/8):0},Ei=class{constructor(e){this.isDataConverted=!1;let{sessionId:t,context:r,tensor:a,dataType:n,shape:i,fallbackDataType:s}=e;this.sessionId=t,this.mlContext=r,this.mlTensor=a,this.dataType=n,this.tensorShape=i,this.fallbackDataType=s}get tensor(){return this.mlTensor}get type(){return this.dataType}get fallbackType(){return this.fallbackDataType}get shape(){return this.tensorShape}get byteLength(){return Ii(this.dataType,this.tensorShape)}destroy(){ue("verbose",()=>"[WebNN] TensorWrapper.destroy"),this.mlTensor.destroy()}write(e){this.mlContext.writeTensor(this.mlTensor,e)}async read(e){if(this.fallbackDataType){let t=await this.mlContext.readTensor(this.mlTensor),r=Si(new Uint8Array(t),this.dataType);if(e){(e instanceof ArrayBuffer?new Uint8Array(e):new Uint8Array(e.buffer,e.byteOffset,e.byteLength)).set(r);return}else return r.buffer}else return e?this.mlContext.readTensor(this.mlTensor,e):this.mlContext.readTensor(this.mlTensor)}canReuseTensor(e,t,r){return this.mlContext===e&&this.dataType===t&&this.tensorShape.length===r.length&&this.tensorShape.every((a,n)=>a===r[n])}setIsDataConverted(e){this.isDataConverted=e}},zi=class{constructor(e,t){this.tensorManager=e,this.wrapper=t}get tensorWrapper(){return this.wrapper}releaseTensor(){this.tensorWrapper&&(this.tensorManager.releaseTensor(this.tensorWrapper),this.wrapper=void 0)}async ensureTensor(e,t,r,a){let n=this.tensorManager.getMLContext(e),i;if(!n.opSupportLimits().input.dataTypes.includes(t)){if(i=Us.get(t),!i||!n.opSupportLimits().input.dataTypes.includes(i))throw new Error(`WebNN backend does not support data type: ${t}`);ue("verbose",()=>`[WebNN] TensorIdTracker.ensureTensor: fallback dataType from ${t} to ${i}`)}if(this.wrapper){if(this.wrapper.canReuseTensor(n,t,r))return this.wrapper.tensor;if(a){if(this.wrapper.byteLength!==Ii(t,r))throw new Error("Unable to copy data to tensor with different size.");this.activeUpload=new Uint8Array(await this.wrapper.read())}this.tensorManager.releaseTensor(this.wrapper)}let s=typeof MLTensorUsage>"u"?void 0:MLTensorUsage.READ|MLTensorUsage.WRITE;return this.wrapper=await this.tensorManager.getCachedTensor(e,t,r,s,!0,!0,i),a&&this.activeUpload&&(this.wrapper.write(this.activeUpload),this.activeUpload=void 0),this.wrapper.tensor}upload(e){let t=e;if(this.wrapper){if(this.wrapper.fallbackType)if(this.wrapper.fallbackType==="int32")t=ha(e,this.wrapper.type),this.wrapper.setIsDataConverted(!0);else throw new Error(`Unsupported fallback data type: ${this.wrapper.fallbackType}`);if(e.byteLength===this.wrapper.byteLength){this.wrapper.write(t);return}else ue("verbose",()=>"Data size does not match tensor size. Releasing tensor."),this.releaseTensor()}this.activeUpload?this.activeUpload.set(t):this.activeUpload=new Uint8Array(t)}async download(e){var t,r;if(this.activeUpload){let a=(t=this.wrapper)!=null&&t.isDataConverted?Si(this.activeUpload,(r=this.wrapper)==null?void 0:r.type):this.activeUpload;if(e){e instanceof ArrayBuffer?new Uint8Array(e).set(a):new Uint8Array(e.buffer,e.byteOffset,e.byteLength).set(a);return}else return a.buffer}if(!this.wrapper)throw new Error("Tensor has not been created.");return e?this.wrapper.read(e):this.wrapper.read()}},qs=class{constructor(e){this.backend=e,this.tensorTrackersById=new Map,this.freeTensors=[],this.externalTensors=new Set}getMLContext(e){let t=this.backend.getMLContext(e);if(!t)throw new Error("MLContext not found for session.");return t}reserveTensorId(){let e=Ti();return this.tensorTrackersById.set(e,new zi(this)),e}releaseTensorId(e){let t=this.tensorTrackersById.get(e);t&&(this.tensorTrackersById.delete(e),t.tensorWrapper&&this.releaseTensor(t.tensorWrapper))}async ensureTensor(e,t,r,a,n){ue("verbose",()=>`[WebNN] TensorManager.ensureTensor {tensorId: ${t}, dataType: ${r}, shape: ${a}, copyOld: ${n}}`);let i=this.tensorTrackersById.get(t);if(!i)throw new Error("Tensor not found.");return i.ensureTensor(e,r,a,n)}upload(e,t){let r=this.tensorTrackersById.get(e);if(!r)throw new Error("Tensor not found.");r.upload(t)}async download(e,t){ue("verbose",()=>`[WebNN] TensorManager.download {tensorId: ${e}, dstBuffer: ${t==null?void 0:t.byteLength}}`);let r=this.tensorTrackersById.get(e);if(!r)throw new Error("Tensor not found.");return r.download(t)}releaseTensorsForSession(e){for(let t of this.freeTensors)t.sessionId===e&&t.destroy();this.freeTensors=this.freeTensors.filter(t=>t.sessionId!==e)}registerTensor(e,t,r,a){let n=this.getMLContext(e),i=Ti(),s=new Ei({sessionId:e,context:n,tensor:t,dataType:r,shape:a});return this.tensorTrackersById.set(i,new zi(this,s)),this.externalTensors.add(s),i}async getCachedTensor(e,t,r,a,n,i,s){let u=this.getMLContext(e);for(let[l,c]of this.freeTensors.entries())if(c.canReuseTensor(u,t,r)){ue("verbose",()=>`[WebNN] Reusing tensor {dataType: ${t}, ${s?`fallbackDataType: ${s},`:""} shape: ${r}`);let f=this.freeTensors.splice(l,1)[0];return f.sessionId=e,f}ue("verbose",()=>`[WebNN] MLContext.createTensor {dataType: ${t}, ${s?`fallbackDataType: ${s},`:""} shape: ${r}}`);let d=await u.createTensor({dataType:s??t,shape:r,dimensions:r,usage:a,writable:n,readable:i});return new Ei({sessionId:e,context:u,tensor:d,dataType:t,shape:r,fallbackDataType:s})}releaseTensor(e){this.externalTensors.has(e)&&this.externalTensors.delete(e),this.freeTensors.push(e)}},Cd=(...e)=>new qs(...e)}),jt,Ws,Od,Im=P(()=>{ee(),Ct(),zd(),Tm(),nt(),jt=new Map([[1,"float32"],[10,"float16"],[6,"int32"],[12,"uint32"],[7,"int64"],[13,"uint64"],[22,"int4"],[21,"uint4"],[3,"int8"],[2,"uint8"],[9,"uint8"]]),Ws=(e,t)=>{if(e===t)return!0;if(e===void 0||t===void 0)return!1;let r=Object.keys(e).sort(),a=Object.keys(t).sort();return r.length===a.length&&r.every((n,i)=>n===a[i]&&e[n]===t[n])},Od=class{constructor(e){this.tensorManager=Cd(this),this.mlContextBySessionId=new Map,this.sessionIdsByMLContext=new Map,this.mlContextCache=[],this.sessionGraphInputs=new Map,this.sessionGraphOutputs=new Map,this.temporaryGraphInputs=[],this.temporaryGraphOutputs=[],this.temporarySessionTensorIds=new Map,Pa(e.logLevel,!!e.debug)}get currentSessionId(){if(this.activeSessionId===void 0)throw new Error("No active session");return this.activeSessionId}onRunStart(e){ue("verbose",()=>`[WebNN] onRunStart {sessionId: ${e}}`),this.activeSessionId=e}onRunEnd(e){ue("verbose",()=>`[WebNN] onRunEnd {sessionId: ${e}}`);let t=this.temporarySessionTensorIds.get(e);if(t){for(let r of t)ue("verbose",()=>`[WebNN] releasing temporary tensor {tensorId: ${r}}`),this.tensorManager.releaseTensorId(r);this.temporarySessionTensorIds.delete(e),this.activeSessionId=void 0}}async createMLContext(e){if(e instanceof GPUDevice){let r=this.mlContextCache.findIndex(a=>a.gpuDevice===e);if(r!==-1)return this.mlContextCache[r].mlContext;{let a=await navigator.ml.createContext(e);return this.mlContextCache.push({gpuDevice:e,mlContext:a}),a}}else if(e===void 0){let r=this.mlContextCache.findIndex(a=>a.options===void 0&&a.gpuDevice===void 0);if(r!==-1)return this.mlContextCache[r].mlContext;{let a=await navigator.ml.createContext();return this.mlContextCache.push({mlContext:a}),a}}let t=this.mlContextCache.findIndex(r=>Ws(r.options,e));if(t!==-1)return this.mlContextCache[t].mlContext;{let r=await navigator.ml.createContext(e);return this.mlContextCache.push({options:e,mlContext:r}),r}}registerMLContext(e,t){this.mlContextBySessionId.set(e,t);let r=this.sessionIdsByMLContext.get(t);r||(r=new Set,this.sessionIdsByMLContext.set(t,r)),r.add(e),this.temporaryGraphInputs.length>0&&(this.sessionGraphInputs.set(e,this.temporaryGraphInputs),this.temporaryGraphInputs=[]),this.temporaryGraphOutputs.length>0&&(this.sessionGraphOutputs.set(e,this.temporaryGraphOutputs),this.temporaryGraphOutputs=[])}onReleaseSession(e){this.sessionGraphInputs.delete(e),this.sessionGraphOutputs.delete(e);let t=this.mlContextBySessionId.get(e);if(!t)return;this.tensorManager.releaseTensorsForSession(e),this.mlContextBySessionId.delete(e);let r=this.sessionIdsByMLContext.get(t);if(r.delete(e),r.size===0){this.sessionIdsByMLContext.delete(t);let a=this.mlContextCache.findIndex(n=>n.mlContext===t);a!==-1&&this.mlContextCache.splice(a,1)}}getMLContext(e){return this.mlContextBySessionId.get(e)}reserveTensorId(){return this.tensorManager.reserveTensorId()}releaseTensorId(e){ue("verbose",()=>`[WebNN] releaseTensorId {tensorId: ${e}}`),this.tensorManager.releaseTensorId(e)}async ensureTensor(e,t,r,a,n){let i=jt.get(r);if(!i)throw new Error(`Unsupported ONNX data type: ${r}`);return this.tensorManager.ensureTensor(e??this.currentSessionId,t,i,a,n)}async createTemporaryTensor(e,t,r){ue("verbose",()=>`[WebNN] createTemporaryTensor {onnxDataType: ${t}, shape: ${r}}`);let a=jt.get(t);if(!a)throw new Error(`Unsupported ONNX data type: ${t}`);let n=this.tensorManager.reserveTensorId();await this.tensorManager.ensureTensor(e,n,a,r,!1);let i=this.temporarySessionTensorIds.get(e);return i?i.push(n):this.temporarySessionTensorIds.set(e,[n]),n}uploadTensor(e,t){if(!ge().shouldTransferToMLTensor)throw new Error("Trying to upload to a MLTensor while shouldTransferToMLTensor is false");ue("verbose",()=>`[WebNN] uploadTensor {tensorId: ${e}, data: ${t.byteLength}}`),this.tensorManager.upload(e,t)}async downloadTensor(e,t){return this.tensorManager.download(e,t)}createMLTensorDownloader(e,t){return async()=>{let r=await this.tensorManager.download(e);return Ua(r,t)}}registerMLTensor(e,t,r,a){let n=jt.get(r);if(!n)throw new Error(`Unsupported ONNX data type: ${r}`);let i=this.tensorManager.registerTensor(e,t,n,a);return ue("verbose",()=>`[WebNN] registerMLTensor {tensor: ${t}, dataType: ${n}, dimensions: ${a}} -> {tensorId: ${i}}`),i}registerMLConstant(e,t,r,a,n,i,s=!1){if(!i)throw new Error("External mounted files are not available.");let u=e;e.startsWith("./")&&(u=e.substring(2));let d=i.get(u);if(!d)throw new Error(`File with name ${u} not found in preloaded files.`);if(t+r>d.byteLength)throw new Error("Out of bounds: data offset and length exceed the external file data size.");let l=d.slice(t,t+r).buffer,c;switch(n.dataType){case"float32":c=new Float32Array(l);break;case"float16":c=typeof Float16Array<"u"&&Float16Array.from?new Float16Array(l):new Uint16Array(l);break;case"int32":c=new Int32Array(l);break;case"uint32":c=new Uint32Array(l);break;case"int64":if(s){let f=ha(new Uint8Array(l),"int64");c=new Int32Array(f.buffer),n.dataType="int32"}else c=new BigInt64Array(l);break;case"uint64":c=new BigUint64Array(l);break;case"int8":c=new Int8Array(l);break;case"int4":case"uint4":case"uint8":c=new Uint8Array(l);break;default:throw new Error(`Unsupported data type: ${n.dataType} in creating WebNN Constant from external data.`)}return ue("verbose",()=>`[WebNN] registerMLConstant {dataType: ${n.dataType}, shape: ${n.shape}}} ${s?"(Note: it was int64 data type and registered to int32 as workaround)":""}`),a.constant(n,c)}registerGraphInput(e){this.temporaryGraphInputs.push(e)}registerGraphOutput(e){this.temporaryGraphOutputs.push(e)}isGraphInput(e,t){let r=this.sessionGraphInputs.get(e);return r?r.includes(t):!1}isGraphOutput(e,t){let r=this.sessionGraphOutputs.get(e);return r?r.includes(t):!1}isGraphInputOutputTypeSupported(e,t,r=!0){let a=this.mlContextBySessionId.get(e),n=jt.get(St(t));return typeof n>"u"?!1:r?!!(a!=null&&a.opSupportLimits().input.dataTypes.includes(n)):!!(a!=null&&a.opSupportLimits().output.dataTypes.includes(n))}flush(){}}}),qa=P(()=>{}),Ci,xr,kr,Vs,Ls,Oi,ma,Gs,Ad,Em=P(()=>{nt(),qa(),Ci=new Map([[64,250],[128,200],[256,200],[512,200],[2048,230],[4096,200],[8192,50],[16384,50],[32768,50],[65536,50],[131072,50],[262144,50],[524288,50],[1048576,50],[2097152,30],[4194304,20],[8388608,10],[12582912,10],[16777216,10],[26214400,15],[33554432,22],[44236800,2],[58982400,6],[67108864,6],[134217728,6],[167772160,6]]),xr=[],kr=e=>Math.ceil(Number(e)/16)*16,Vs=e=>{for(let t=0;t<xr.length;t++){let r=xr[t];if(e<=r)return r}return Math.ceil(e/16)*16},Ls=1,Oi=()=>Ls++,ma=async(e,t,r,a)=>{let n=kr(r),i=e.device.createBuffer({size:n,usage:GPUBufferUsage.COPY_DST|GPUBufferUsage.MAP_READ});try{let s=e.getCommandEncoder();e.endComputePass(),s.copyBufferToBuffer(t,0,i,0,n),e.flush(),await i.mapAsync(GPUMapMode.READ);let u=i.getMappedRange();if(a){let d=a();return d.set(new Uint8Array(u,0,r)),d}else return new Uint8Array(u.slice(0,r))}finally{i.destroy()}},Gs=class{constructor(e){this.backend=e,this.storageCache=new Map,this.freeBuffers=new Map,this.freeUniformBuffers=new Map,this.buffersPending=[],this.capturedPendingBuffers=new Map;for(let[t]of Ci)xr.push(t),this.freeBuffers.set(t,[]),this.freeUniformBuffers.set(t,[]);this.sessionCount=0}upload(e,t){let r=t.buffer,a=t.byteOffset,n=t.byteLength,i=kr(n),s=this.storageCache.get(e);if(!s)throw new Error("gpu data for uploading does not exist");if(Number(s.originalSize)!==n)throw new Error(`inconsistent data size. gpu data size=${s.originalSize}, data size=${n}`);let u=this.backend.device.createBuffer({mappedAtCreation:!0,size:i,usage:GPUBufferUsage.MAP_WRITE|GPUBufferUsage.COPY_SRC}),d=u.getMappedRange();new Uint8Array(d).set(new Uint8Array(r,a,n)),u.unmap();let l=this.backend.device.createCommandEncoder();l.copyBufferToBuffer(u,0,s.gpuData.buffer,0,i),this.backend.device.queue.submit([l.finish()]),u.destroy(),ue("verbose",()=>`[WebGPU] GpuDataManager.upload(id=${e})`)}memcpy(e,t){let r=this.storageCache.get(e);if(!r)throw new Error("source gpu data for memcpy does not exist");let a=this.storageCache.get(t);if(!a)throw new Error("destination gpu data for memcpy does not exist");if(r.originalSize!==a.originalSize)throw new Error("inconsistent source and destination gpu data size");let n=kr(r.originalSize),i=this.backend.getCommandEncoder();this.backend.endComputePass(),i.copyBufferToBuffer(r.gpuData.buffer,0,a.gpuData.buffer,0,n)}registerExternalBuffer(e,t,r){let a;if(r){if(a=r[0],e===r[1])return ue("verbose",()=>`[WebGPU] GpuDataManager.registerExternalBuffer(size=${t}) => id=${a}, buffer is the same, skip.`),a;if(this.backend.capturedCommandList.has(this.backend.currentSessionId))throw new Error(`Registering a different external buffer under graph capture mode is not supported yet.
             Please use the previous external buffer!`)}else a=Oi();return this.storageCache.set(a,{gpuData:{id:a,type:0,buffer:e},originalSize:t}),ue("verbose",()=>`[WebGPU] GpuDataManager.registerExternalBuffer(size=${t}) => id=${a}, registered.`),a}unregisterExternalBuffer(e){e!==void 0&&(this.storageCache.delete(e),ue("verbose",()=>`[WebGPU] GpuDataManager.unregisterExternalBuffer() => id=${e}`))}create(e,t=GPUBufferUsage.STORAGE|GPUBufferUsage.COPY_SRC|GPUBufferUsage.COPY_DST){let r=Vs(e),a,n=(t&GPUBufferUsage.STORAGE)===GPUBufferUsage.STORAGE,i=(t&GPUBufferUsage.UNIFORM)===GPUBufferUsage.UNIFORM;if(n||i){let u=(n?this.freeBuffers:this.freeUniformBuffers).get(r);u?u.length>0?a=u.pop():a=this.backend.device.createBuffer({size:r,usage:t}):a=this.backend.device.createBuffer({size:r,usage:t})}else a=this.backend.device.createBuffer({size:r,usage:t});let s={id:Oi(),type:0,buffer:a};return this.storageCache.set(s.id,{gpuData:s,originalSize:Number(e)}),ue("verbose",()=>`[WebGPU] GpuDataManager.create(size=${e}) => id=${s.id}`),s}get(e){var t;return(t=this.storageCache.get(e))==null?void 0:t.gpuData}release(e){let t=typeof e=="bigint"?Number(e):e,r=this.storageCache.get(t);if(!r){if(this.storageCache.size===0)return 0;throw new Error("releasing data does not exist")}return ue("verbose",()=>`[WebGPU] GpuDataManager.release(id=${t}), gpuDataId=${r.gpuData.id}`),this.storageCache.delete(t),this.buffersPending.push(r.gpuData.buffer),r.originalSize}async download(e,t){let r=this.storageCache.get(Number(e));if(!r)throw new Error("data does not exist");await ma(this.backend,r.gpuData.buffer,r.originalSize,t)}refreshPendingBuffers(){if(this.buffersPending.length!==0)if(this.backend.sessionStatus==="default"){for(let e of this.buffersPending){let t=Ci.get(e.size);if((e.usage&GPUBufferUsage.STORAGE)===GPUBufferUsage.STORAGE){let r=this.freeBuffers.get(e.size)||[];t===void 0||r.length>=t?e.destroy():r.push(e)}else if((e.usage&GPUBufferUsage.UNIFORM)===GPUBufferUsage.UNIFORM){let r=this.freeUniformBuffers.get(e.size)||[];t===void 0||r.length>=t?e.destroy():r.push(e)}else e.destroy()}this.buffersPending=[]}else{let e=this.capturedPendingBuffers.get(this.backend.currentSessionId);e||(e=[],this.capturedPendingBuffers.set(this.backend.currentSessionId,e));for(let t of this.buffersPending)e.push(t);this.buffersPending=[]}}dispose(){this.freeBuffers.forEach(e=>{e.forEach(t=>{t.destroy()})}),this.freeUniformBuffers.forEach(e=>{e.forEach(t=>{t.destroy()})}),this.storageCache.forEach(e=>{e.gpuData.buffer.destroy()}),this.capturedPendingBuffers.forEach(e=>{e.forEach(t=>{t.destroy()})}),this.storageCache=new Map,this.freeBuffers=new Map,this.freeUniformBuffers=new Map,this.capturedPendingBuffers=new Map}onCreateSession(){this.sessionCount+=1}onReleaseSession(e){let t=this.capturedPendingBuffers.get(e);t&&(t.forEach(r=>{r.destroy()}),this.capturedPendingBuffers.delete(e)),this.sessionCount-=1,this.sessionCount===0&&(ue("warning",()=>"[WebGPU] Clearing webgpu buffer cache"),this.storageCache.forEach(r=>{r.gpuData.buffer.destroy()}),this.storageCache=new Map)}},Ad=(...e)=>new Gs(...e)}),Hs,pe,ve=P(()=>{Hs=class{constructor(e){Object.assign(this,e)}get cacheKey(){return this.key||(this.key=Object.getOwnPropertyNames(this).sort().map(e=>`${this[e]}`).join(";")),this.key}},pe=e=>new Hs(e)}),Ut,Sr,ke,Ee,Q,$e,ga,Dt,mt,j,Kt,R,H,Bd,Wa,Fs,Rd,ne=P(()=>{ee(),ae(),Ut=64,Sr=(e,t)=>{if(t===3)throw new Error("vec3 has same alignment as vec4, use vec4 instead");switch(Number(e)){case 10:return t>1?`vec${t}<f16>`:"f16";case 1:return t>1?`vec${t}<f32>`:"f32";case 6:return t>1?`vec${t}<i32>`:"i32";case 12:return t>1?`vec${t}<u32>`:"u32";case 7:if(t>1)throw new Error("currently not supported vecX of uint64 yet");return["vec2<u32>","i32"];case 13:if(t>1)throw new Error("currently not supported vecX of uint64 yet");return["vec2<u32>","u32"];case 9:if(t!==4)throw new Error("bool must be vec4");return["u32","vec4<bool>"];case 22:return"i32";case 21:return"u32";default:throw new Error(`Unknown data type: ${e}`)}},ke=(e,t=1)=>{let r=Sr(e,t);return typeof r=="string"?r:r[0]},Ee=(e,t=1)=>{let r=Sr(e,t);return typeof r=="string"?r:r[1]},Q=(...e)=>{let t=[];return e.forEach(r=>{r.length!==0&&t.push({type:12,data:r},{type:12,data:O.computeStrides(r)})}),t},$e=e=>e%4===0?4:e%2===0?2:1,ga=(e="f32",t,r="0")=>!t||t===1?`${e}(${r})`:`vec${t}<${e}>(${r})`,Dt=(e,t,r)=>e==="f32"?r:t===1?`f32(${r})`:`vec${t}<f32>(${r})`,mt=(e,t)=>t===4?`(${e}.x + ${e}.y + ${e}.z + ${e}.w)`:t===2?`(${e}.x + ${e}.y)`:t===3?`(${e}.x + ${e}.y + ${e}.z)`:e,j=(e,t,r,a)=>e.startsWith("uniforms.")&&r>4?typeof t=="string"?a==="f16"?`${e}[(${t}) / 8][(${t}) % 8 / 4][(${t}) % 8 % 4]`:`${e}[(${t}) / 4][(${t}) % 4]`:a==="f16"?`${e}[${Math.floor(t/8)}][${Math.floor(t%8/4)}][${t%8%4}]`:`${e}[${Math.floor(t/4)}][${t%4}]`:r>1?`${e}[${t}]`:e,Kt=(e,t,r,a,n)=>{let i=typeof r=="number",s=i?r:r.length,u=[...new Array(s).keys()],d=s<2?"u32":s<=4?`vec${s}<u32>`:`array<u32, ${s}>`,l=Sr(t,n),c=typeof l=="string"?l:l[1],f=typeof l=="string"?l:l[0],m={indices:d,value:c,storage:f,tensor:t},g=N=>typeof N=="string"?N:`${N}u`,_={offsetToIndices:!1,indicesToOffset:!1,broadcastedIndicesToOffset:!1,set:!1,setByIndices:!1,get:!1,getByIndices:!1},b=i?"uniforms.":"",x=`${b}${e}_shape`,$=`${b}${e}_strides`,w="";for(let N=0;N<s-1;N++)w+=`
    let dim${N} = current / ${j($,N,s)};
    let rest${N} = current % ${j($,N,s)};
    indices[${N}] = dim${N};
    current = rest${N};
    `;w+=`indices[${s-1}] = current;`;let S=s<2?"":`
  fn o2i_${e}(offset: u32) -> ${m.indices} {
    var indices: ${m.indices};
    var current = offset;
    ${w}
    return indices;
  }`,k=N=>(_.offsetToIndices=!0,s<2?N:`o2i_${e}(${N})`),T=[];if(s>=2)for(let N=s-1;N>=0;N--)T.push(`${j($,N,s)} * (indices[${N}])`);let E=s<2?"":`
  fn i2o_${e}(indices: ${m.indices}) -> u32 {
    return ${T.join("+")};
  }`,z=N=>(_.indicesToOffset=!0,s<2?N:`i2o_${e}(${N})`),C=(...N)=>s===0?"0u":`${m.indices}(${N.map(g).join(",")})`,A=(N,U)=>s<2?`${N}`:`${j(N,U,s)}`,q=(N,U,V)=>s<2?`${N}=${V};`:`${j(N,U,s)}=${V};`,X={},G=(N,U)=>{_.broadcastedIndicesToOffset=!0;let V=`${U.name}broadcastedIndicesTo${e}Offset`;if(V in X)return`${V}(${N})`;let te=[];for(let Te=s-1;Te>=0;Te--){let M=U.indicesGet("outputIndices",Te+U.rank-s);te.push(`${A($,Te)} * (${M} % ${A(x,Te)})`)}return X[V]=`fn ${V}(outputIndices: ${U.type.indices}) -> u32 {
             return ${te.length>0?te.join("+"):"0u"};
           }`,`${V}(${N})`},Z=(N,U)=>(()=>{if(m.storage===m.value)return`${e}[${N}]=${U};`;if(m.storage==="vec2<u32>"&&m.value==="i32")return`${e}[${N}]=vec2<u32>(u32(${U}), select(0u, 0xFFFFFFFFu, ${U} < 0));`;if(m.storage==="vec2<u32>"&&m.value==="u32")return`${e}[${N}]=vec2<u32>(u32(${U}), 0u);`;if(m.storage==="u32"&&m.value==="vec4<bool>")return`${e}[${N}]=dot(vec4<u32>(0x1, 0x100, 0x10000, 0x1000000), vec4<u32>(${U}));`;throw new Error(`not supported combination of storage type ${m.storage} and value type ${m.value} yet`)})(),oe=N=>(()=>{if(m.storage===m.value)return`${e}[${N}]`;if(m.storage==="vec2<u32>"&&m.value==="i32")return`i32(${e}[${N}].x)`;if(m.storage==="vec2<u32>"&&m.value==="u32")return`u32(${e}[${N}].x)`;if(m.storage==="u32"&&m.value==="vec4<bool>")return`vec4<bool>(bool(${e}[${N}] & 0xFFu), bool(${e}[${N}] & 0xFF00u), bool(${e}[${N}] & 0xFF0000u), bool(${e}[${N}] & 0xFF000000u))`;throw new Error(`not supported combination of storage type ${m.storage} and value type ${m.value} yet`)})(),re=s<2?"":`
  fn get_${e}ByIndices(indices: ${m.indices}) -> ${c} {
    return ${oe(`i2o_${e}(indices)`)};
  }`,L=s<2?"":(()=>{let N=u.map(V=>`d${V}: u32`).join(", "),U=u.map(V=>`d${V}`).join(", ");return`
  fn get_${e}(${N}) -> ${c} {
    return get_${e}ByIndices(${C(U)});
  }`})(),ie=(...N)=>{if(N.length!==s)throw new Error(`indices length must be ${s}`);let U=N.map(g).join(",");return s===0?oe("0u"):s===1?oe(U[0]):(_.get=!0,_.getByIndices=!0,_.indicesToOffset=!0,`get_${e}(${U})`)},F=N=>s<2?oe(N):(_.getByIndices=!0,_.indicesToOffset=!0,`get_${e}ByIndices(${N})`),Y=s<2?"":`
  fn set_${e}ByIndices(indices: ${m.indices}, value: ${c}) {
    ${Z(`i2o_${e}(indices)`,"value")}
  }`,ye=s<2?"":(()=>{let N=u.map(V=>`d${V}: u32`).join(", "),U=u.map(V=>`d${V}`).join(", ");return`
  fn set_${e}(${N}, value: ${c}) {
    set_${e}ByIndices(${C(U)}, value);
  }`})();return{impl:()=>{let N=[],U=!1;return _.offsetToIndices&&(N.push(S),U=!0),_.indicesToOffset&&(N.push(E),U=!0),_.broadcastedIndicesToOffset&&(Object.values(X).forEach(V=>N.push(V)),U=!0),_.set&&(N.push(ye),U=!0),_.setByIndices&&(N.push(Y),U=!0),_.get&&(N.push(L),U=!0),_.getByIndices&&(N.push(re),U=!0),!i&&U&&N.unshift(`const ${x} = ${m.indices}(${r.join(",")});`,`const ${$} = ${m.indices}(${O.computeStrides(r).join(",")});`),N.join(`
`)},type:m,offsetToIndices:k,indicesToOffset:z,broadcastedIndicesToOffset:G,indices:C,indicesGet:A,indicesSet:q,set:(...N)=>{if(N.length!==s+1)throw new Error(`indices length must be ${s}`);let U=N[s];if(typeof U!="string")throw new Error("value must be string");let V=N.slice(0,s).map(g).join(",");return s===0?Z("0u",U):s===1?Z(V[0],U):(_.set=!0,_.setByIndices=!0,_.indicesToOffset=!0,`set_${e}(${V}, ${U})`)},setByOffset:Z,setByIndices:(N,U)=>s<2?Z(N,U):(_.setByIndices=!0,_.indicesToOffset=!0,`set_${e}ByIndices(${N}, ${U});`),get:ie,getByOffset:oe,getByIndices:F,usage:a,name:e,strides:$,shape:x,rank:s}},R=(e,t,r,a=1)=>Kt(e,t,r,"input",a),H=(e,t,r,a=1)=>Kt(e,t,r,"output",a),Bd=(e,t,r)=>Kt(e,t,r,"atomicOutput",1),Wa=(e,t,r,a=1)=>Kt(e,t,r,"internal",a),Fs=class{constructor(e,t){this.normalizedDispatchGroup=e,this.limits=t,this.internalVariables=[],this.variables=[],this.uniforms=[],this.variableIndex=0}guardAgainstOutOfBoundsWorkgroupSizes(e){return`if (global_idx >= ${typeof e=="number"?`${e}u`:e}) { return; }`}mainStart(e=Ut){let t=typeof e=="number"?e:e[0],r=typeof e=="number"?1:e[1],a=typeof e=="number"?1:e[2];if(t>this.limits.maxComputeWorkgroupSizeX||r>this.limits.maxComputeWorkgroupSizeY||a>this.limits.maxComputeWorkgroupSizeZ)throw new Error(`workgroup size [${t}, ${r}, ${a}] exceeds the maximum workgroup size [${this.limits.maxComputeWorkgroupSizeX}, ${this.limits.maxComputeWorkgroupSizeY}, ${this.limits.maxComputeWorkgroupSizeZ}].`);if(t*r*a>this.limits.maxComputeInvocationsPerWorkgroup)throw new Error(`workgroup size [${t}, ${r}, ${a}] exceeds the maximum workgroup invocations ${this.limits.maxComputeInvocationsPerWorkgroup}.`);let n=this.normalizedDispatchGroup[1]===1&&this.normalizedDispatchGroup[2]===1,i=n?`@builtin(global_invocation_id) global_id : vec3<u32>,
    @builtin(workgroup_id) workgroup_id : vec3<u32>,
    @builtin(local_invocation_index) local_idx : u32,
    @builtin(local_invocation_id) local_id : vec3<u32>`:`@builtin(global_invocation_id) global_id : vec3<u32>,
                                             @builtin(local_invocation_id) local_id : vec3<u32>,
    @builtin(local_invocation_index) local_idx : u32,
    @builtin(workgroup_id) workgroup_id : vec3<u32>,
    @builtin(num_workgroups) num_workgroups : vec3<u32>`,s=n?`let global_idx = global_id.x;
         let workgroup_index = workgroup_id.x;`:`let workgroup_index = workgroup_id.z * num_workgroups[0] * num_workgroups[1] +
             workgroup_id.y * num_workgroups[0] + workgroup_id.x;
         let global_idx = workgroup_index * ${t*r*a}u + local_idx;`;return`@compute @workgroup_size(${t}, ${r}, ${a})
  fn main(${i}) {
    ${s}
  `}appendVariableUniforms(e){e.rank!==0&&(e.shape.startsWith("uniforms.")&&this.uniforms.push({name:e.shape.replace("uniforms.",""),type:"u32",length:e.rank}),e.strides.startsWith("uniforms.")&&this.uniforms.push({name:e.strides.replace("uniforms.",""),type:"u32",length:e.rank}))}declareVariable(e,t){if(e.usage==="internal")throw new Error("cannot use internal variable with declareVariable(). use registerInternalVariables() instead.");this.variables.push(e),this.appendVariableUniforms(e);let r=e.usage==="input"?"read":"read_write",a=e.usage==="atomicOutput"?"atomic<i32>":e.type.storage;return`@group(0) @binding(${t}) var<storage, ${r}> ${e.name}: array<${a}>;`}declareVariables(...e){return e.map(t=>this.declareVariable(t,this.variableIndex++)).join(`
`)}registerInternalVariable(e){if(e.usage!=="internal")throw new Error("cannot use input or output variable with registerInternalVariable(). use declareVariables() instead.");this.internalVariables.push(e),this.appendVariableUniforms(e)}registerInternalVariables(...e){return e.forEach(t=>this.registerInternalVariable(t)),this}registerUniform(e,t,r=1){return this.uniforms.push({name:e,type:t,length:r}),this}registerUniforms(e){return this.uniforms=this.uniforms.concat(e),this}uniformDeclaration(){if(this.uniforms.length===0)return"";let e=[];for(let{name:t,type:r,length:a}of this.uniforms)if(a&&a>4)r==="f16"?e.push(`@align(16) ${t}:array<mat2x4<${r}>, ${Math.ceil(a/8)}>`):e.push(`${t}:array<vec4<${r}>, ${Math.ceil(a/4)}>`);else{let n=a==null||a===1?r:`vec${a}<${r}>`;e.push(`${t}:${n}`)}return`
      struct Uniforms { ${e.join(", ")} };
      @group(0) @binding(${this.variableIndex}) var<uniform> uniforms: Uniforms;`}get additionalImplementations(){return this.uniformDeclaration()+this.variables.map(e=>e.impl()).join(`
`)+this.internalVariables.map(e=>e.impl()).join(`
`)}get variablesInfo(){if(this.uniforms.length===0)return;let e=t=>[12,10,1,6][["u32","f16","f32","i32"].indexOf(t)];return this.uniforms.map(t=>[e(t.type),t.length??1])}},Rd=(e,t)=>new Fs(e,t)}),js,Ai,Ks,Zs,Qs,Xs,Me,Nd,Md,gt=P(()=>{ee(),ae(),ve(),ne(),js=(e,t)=>{if(!e||e.length!==1)throw new Error("Transpose requires 1 input.");if(t.length!==0&&t.length!==e[0].dims.length)throw new Error(`perm size ${t.length} does not match input rank ${e[0].dims.length}`)},Ai=(e,t)=>t.length!==0?t:[...new Array(e).keys()].reverse(),Ks=(e,t)=>O.sortBasedOnPerm(e,Ai(e.length,t)),Zs=(e,t,r,a)=>{let n=`fn perm(i: ${a.type.indices}) -> ${r.type.indices} {
    var a: ${r.type.indices};`;for(let i=0;i<t;++i)n+=`a[${e[i]}]=i[${i}];`;return n+="return a;}"},Qs=(e,t)=>{let r=[],a=[];for(let n=0;n<e.length;++n)e[n]!==1&&r.push(e[n]),e[t[n]]!==1&&a.push(t[n]);return{newShape:r,newPerm:a}},Xs=(e,t)=>{let r=0;for(let a=0;a<e.length;++a)if(t[e[a]]!==1){if(e[a]<r)return!1;r=e[a]}return!0},Me=(e,t)=>{let r=e.dataType,a=e.dims.length,n=Ai(a,t),i=Ks(e.dims,n),s=e.dims,u=i,d=a<2||Xs(n,e.dims),l;if(d)return l=_=>{let b=R("input",r,s,4),x=H("output",r,u,4);return`
  ${_.registerUniform("output_size","u32").declareVariables(b,x)}
  ${_.mainStart()}
    ${_.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}
    output[global_idx] = input[global_idx];
  }`},{name:"TransposeCopy",shaderCache:{inputDependencies:["type"]},getRunData:()=>{let _=O.size(i);return{outputs:[{dims:i,dataType:e.dataType}],dispatchGroup:{x:Math.ceil(_/64/4)},programUniforms:[{type:12,data:Math.ceil(_/4)}]}},getShaderSource:l};let{newShape:c,newPerm:f}=Qs(e.dims,n),m=O.areEqual(f,[2,3,1]),g=O.areEqual(f,[3,1,2]);if(c.length===2||m||g){s=m?[c[0],c[1]*c[2]]:g?[c[0]*c[1],c[2]]:c,u=[s[1],s[0]];let _=16;return l=b=>{let x=R("a",r,s.length),$=H("output",r,u.length);return`
  ${b.registerUniform("output_size","u32").declareVariables(x,$)}
  var<workgroup> tile : array<array<${$.type.value}, ${_+1}>, ${_}>;
  ${b.mainStart([_,_,1])}
    let stride = (uniforms.output_shape[1] - 1) / ${_} + 1;
    let workgroup_id_x = workgroup_index % stride;
    let workgroup_id_y = workgroup_index / stride;
    let input_col = workgroup_id_y * ${_}u + local_id.x;
    let input_row = workgroup_id_x * ${_}u + local_id.y;
    if (input_row < uniforms.a_shape[0] && input_col < uniforms.a_shape[1]) {
      tile[local_id.y][local_id.x] = ${x.getByIndices(`${x.type.indices}(input_row, input_col)`)};
    }
    workgroupBarrier();

    let output_col = workgroup_id_x * ${_}u + local_id.x;
    let output_row = workgroup_id_y * ${_}u + local_id.y;
    if (output_row < uniforms.output_shape[0] && output_col < uniforms.output_shape[1]) {
      ${$.setByIndices(`${$.type.indices}(output_row, output_col)`,"tile[local_id.x][local_id.y]")}
    }
  }`},{name:"TransposeShared",shaderCache:{inputDependencies:["type"]},getRunData:()=>{let b=O.size(i);return{outputs:[{dims:i,dataType:e.dataType}],dispatchGroup:{x:Math.ceil(u[1]/_),y:Math.ceil(u[0]/_)},programUniforms:[{type:12,data:b},...Q(s,u)]}},getShaderSource:l}}return l=_=>{let b=R("a",r,s.length),x=H("output",r,u.length);return`
  ${_.registerUniform("output_size","u32").declareVariables(b,x)}

  ${Zs(n,a,b,x)}

  ${_.mainStart()}
    ${_.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}

    let indices = ${x.offsetToIndices("global_idx")};
    let aIndices = perm(indices);

    ${x.setByOffset("global_idx",b.getByIndices("aIndices"))}
  }`},{name:"Transpose",shaderCache:{hint:`${t}`,inputDependencies:["rank"]},getRunData:()=>{let _=O.size(i);return{outputs:[{dims:i,dataType:e.dataType}],dispatchGroup:{x:Math.ceil(_/64)},programUniforms:[{type:12,data:_},...Q(s,u)]}},getShaderSource:l}},Nd=(e,t)=>{js(e.inputs,t.perm),e.compute(Me(e.inputs[0],t.perm))},Md=e=>pe({perm:e.perm})}),Ys,Js,eo,to,ro,io,ao,no,so,oo,qe,Dd,Pd,Ud,qd,Wd,Vd,Ld,Gd,Hd,Fd,zm=P(()=>{ee(),ae(),ne(),Va(),gt(),Ys={max:"select(bestValue, candidate, candidate > bestValue)",min:"select(bestValue, candidate, candidate < bestValue)",mean:"bestValue + candidate",sum:"bestValue + candidate",prod:"bestValue * candidate",sumSquare:"bestValue + candidate * candidate",logSumExp:"bestValue + exp(candidate)",l1:"bestValue + abs(candidate)",l2:"bestValue + candidate * candidate",logSum:"bestValue + candidate"},Js={max:"select(bestValue, candidate, candidate > bestValue)",min:"select(bestValue, candidate, candidate < bestValue)",mean:"bestValue + candidate",sum:"bestValue + candidate",prod:"bestValue * candidate",sumSquare:"bestValue + candidate",logSumExp:"bestValue + candidate",l1:"bestValue + candidate",l2:"bestValue + candidate",logSum:"bestValue + candidate"},eo={max:"_A[offset]",min:"_A[offset]",mean:"0",sum:"0",prod:"1",sumSquare:"0",logSumExp:"0",l1:"0",l2:"0",logSum:"0"},to={max:"bestValue",min:"bestValue",sum:"bestValue",prod:"bestValue",sumSquare:"bestValue",logSumExp:"log(bestValue)",l1:"bestValue",l2:"sqrt(bestValue)",logSum:"log(bestValue)"},ro=(e,t)=>{let r=[];for(let a=t-e;a<t;++a)r.push(a);return r},io=(e,t)=>{let r=[],a=e.length;for(let i=0;i<a;i++)t.indexOf(i)===-1&&r.push(e[i]);let n=t.map(i=>e[i]);return[r,n]},ao=(e,t)=>{let r=e.length+t.length,a=[],n=0;for(let i=0;i<r;i++)t.indexOf(i)===-1?a.push(e[n++]):a.push(1);return a},no=(e,t)=>{for(let r=0;r<e.length;++r)if(e[e.length-r-1]!==t-1-r)return!1;return!0},so=(e,t)=>{let r=[];if(!no(e,t)){for(let a=0;a<t;++a)e.indexOf(a)===-1&&r.push(a);e.forEach(a=>r.push(a))}return r},oo=(e,t,r,a,n,i,s)=>{let u=r[0].dims,d=O.size(i),l=O.size(s),c=R("_A",r[0].dataType,u),f=H("output",n,i),m=64;d===1&&(m=256);let g=`
          var<workgroup> aBestValues : array<f32, ${m}>;
       `,_=b=>`
        ${b.registerUniform("reduceSize","u32").declareVariables(c,f)}
        ${g}
        fn DIV_CEIL(a : u32, b : u32) -> u32 {
          return ((a - 1u) / b + 1u);
         }
         ${b.mainStart(m)}

          let outputIndex = global_idx / ${m};
          let offset = outputIndex * uniforms.reduceSize;

          var bestValue = f32(${eo[a]});
          let Length = uniforms.reduceSize;
          for (var k = local_idx; k < Length; k = k + ${m}) {
           let candidate = f32(${c.getByOffset("offset + k")});
           bestValue = ${Ys[a]};
          }
          aBestValues[local_idx] = bestValue;
          workgroupBarrier();

         var reduceSize = min(Length, ${m}u);
         for (var currentSize = reduceSize / 2u; reduceSize > 1u;
             currentSize = reduceSize / 2u) {
           let interval = DIV_CEIL(reduceSize, 2u);
           if (local_idx < currentSize) {
            let candidate = aBestValues[local_idx + interval];
            bestValue = ${Js[a]};
            aBestValues[local_idx] = bestValue;
           }
           reduceSize = interval;
           workgroupBarrier();
         }

         if (local_idx == 0u) {
          ${f.setByOffset("outputIndex",`${a==="mean"?`${f.type.storage}(bestValue / f32(uniforms.reduceSize))`:`${f.type.storage}(${to[a]})`}`)};
         }
        }`;return{name:e,shaderCache:{hint:`${t};${m}`,inputDependencies:["type"]},getShaderSource:_,getRunData:()=>({outputs:[{dims:i,dataType:n}],dispatchGroup:{x:d},programUniforms:[{type:12,data:l}]})}},qe=(e,t,r,a)=>{let n=e.inputs.length===1?r:_a(e.inputs,r),i=n.axes;i.length===0&&!n.noopWithEmptyAxes&&(i=e.inputs[0].dims.map((g,_)=>_));let s=O.normalizeAxes(i,e.inputs[0].dims.length),u=s,d=e.inputs[0],l=so(u,e.inputs[0].dims.length);l.length>0&&(d=e.compute(Me(e.inputs[0],l),{inputs:[0],outputs:[-1]})[0],u=ro(u.length,d.dims.length));let[c,f]=io(d.dims,u),m=c;n.keepDims&&(m=ao(c,s)),e.compute(oo(t,n.cacheKey,[d],a,e.inputs[0].dataType,m,f),{inputs:[d]})},Dd=(e,t)=>{qe(e,"ReduceMeanShared",t,"mean")},Pd=(e,t)=>{qe(e,"ReduceL1Shared",t,"l1")},Ud=(e,t)=>{qe(e,"ReduceL2Shared",t,"l2")},qd=(e,t)=>{qe(e,"ReduceLogSumExpShared",t,"logSumExp")},Wd=(e,t)=>{qe(e,"ReduceMaxShared",t,"max")},Vd=(e,t)=>{qe(e,"ReduceMinShared",t,"min")},Ld=(e,t)=>{qe(e,"ReduceProdShared",t,"prod")},Gd=(e,t)=>{qe(e,"ReduceSumShared",t,"sum")},Hd=(e,t)=>{qe(e,"ReduceSumSquareShared",t,"sumSquare")},Fd=(e,t)=>{qe(e,"ReduceLogSumShared",t,"logSum")}}),We,uo,Ur,_a,Ve,lo,po,co,fo,ho,mo,go,_o,yo,bo,Le,jd,Kd,Zd,Qd,Xd,Yd,Jd,ep,tp,rp,Va=P(()=>{ee(),ae(),ve(),ne(),zm(),We=e=>{if(!e||e.length===0||e.length>2)throw new Error("Reduce op requires 1 or 2 inputs.");if(e.length===2&&e[1].dims.length!==1)throw new Error("Invalid axes input dims.")},uo=e=>["","",`var value = ${e.getByIndices("input_indices")};`,""],Ur=(e,t,r,a,n,i,s=!1,u=!1)=>{let d=[],l=r[0].dims,c=l.length,f=O.normalizeAxes(n,c),m=!u&&f.length===0;l.forEach((b,x)=>{m||f.indexOf(x)>=0?s&&d.push(1):d.push(b)});let g=d.length,_=O.size(d);return{name:e,shaderCache:t,getShaderSource:b=>{let x=[],$=R("_A",r[0].dataType,c),w=H("output",i,g),S=a($,w,f),k=S[2];for(let T=0,E=0;T<c;T++)m||f.indexOf(T)>=0?(s&&E++,k=`for(var j${T}: u32 = 0; j${T} < ${l[T]}; j${T}++) {
                  ${S[2].includes("last_index")?`let last_index = j${T};`:""}
                  ${$.indicesSet("input_indices",T,`j${T}`)}
                  ${k}
                }`):(x.push(`${$.indicesSet("input_indices",T,w.indicesGet("output_indices",E))};`),E++);return`

        ${b.registerUniform("output_size","u32").declareVariables($,w)}

        ${b.mainStart()}
          ${b.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}
          var input_indices: ${$.type.indices};
          let output_indices = ${w.offsetToIndices("global_idx")};

          ${x.join(`
`)}
          ${S[0]}       // init ops for reduce max/min
          ${S[1]}
          ${k}
          ${S[3]}
          ${S.length===4?w.setByOffset("global_idx","value"):S.slice(4).join(`
`)}
        }`},getRunData:()=>({outputs:[{dims:d,dataType:i}],dispatchGroup:{x:Math.ceil(_/64)},programUniforms:[{type:12,data:_},...Q(l,d)]})}},_a=(e,t)=>{let r=[];return e[1].dims[0]>0&&e[1].getBigInt64Array().forEach(a=>r.push(Number(a))),pe({axes:r,keepDims:t.keepDims,noopWithEmptyAxes:t.noopWithEmptyAxes})},Ve=(e,t,r,a)=>{let n=e.inputs,i=n.length===1?r:_a(n,r);e.compute(Ur(t,{hint:i.cacheKey,inputDependencies:["rank"]},[n[0]],i.noopWithEmptyAxes&&i.axes.length===0?uo:a,i.axes,n[0].dataType,i.keepDims,i.noopWithEmptyAxes),{inputs:[0]})},lo=(e,t)=>{We(e.inputs),Ve(e,"ReduceLogSum",t,(r,a)=>[`var value = ${a.type.storage}(0);`,"",`value += ${r.getByIndices("input_indices")};`,"value = log(value);"])},po=(e,t)=>{We(e.inputs),Ve(e,"ReduceL1",t,(r,a)=>[`var value = ${a.type.storage}(0);`,"",`value += abs(${r.getByIndices("input_indices")});`,""])},co=(e,t)=>{We(e.inputs),Ve(e,"ReduceL2",t,(r,a)=>[`var t = ${a.type.value}(0); var value = ${a.type.value}(0);`,"",`t = ${r.getByIndices("input_indices")}; value += (t * t);`,"value = sqrt(value);"])},fo=(e,t)=>{We(e.inputs),Ve(e,"ReduceLogSumExp",t,(r,a)=>[`var value = ${a.type.storage}(0);`,"",`value += exp(${r.getByIndices("input_indices")});`,"value = log(value);"])},ho=(e,t)=>{We(e.inputs),Ve(e,"ReduceMax",t,(r,a,n)=>{let i=[];for(let s=0;s<r.rank;s++)(n.indexOf(s)>=0||n.length===0)&&i.push(r.indicesSet("input_indices",s,0));return[`${i.join(`
`)}`,`var value = ${r.getByIndices("input_indices")};`,`value = max(value, ${r.getByIndices("input_indices")});`,""]})},mo=(e,t)=>{We(e.inputs),Ve(e,"ReduceMean",t,(r,a,n)=>{let i=1;for(let s=0;s<r.rank;s++)(n.indexOf(s)>=0||n.length===0)&&(i*=e.inputs[0].dims[s]);return["var sum = f32(0);","",`sum += f32(${r.getByIndices("input_indices")});`,`let value = ${a.type.value}(sum / ${i});`]})},go=(e,t)=>{We(e.inputs),Ve(e,"ReduceMin",t,(r,a,n)=>{let i=[];for(let s=0;s<r.rank;s++)(n.indexOf(s)>=0||n.length===0)&&i.push(`input_indices[${s}] = 0;`);return[`${i.join(`
`)}`,`var value = ${r.getByIndices("input_indices")};`,`value = min(value, ${r.getByIndices("input_indices")});`,""]})},_o=(e,t)=>{We(e.inputs),Ve(e,"ReduceProd",t,(r,a)=>[`var value = ${a.type.storage}(1);`,"",`value *= ${r.getByIndices("input_indices")};`,""])},yo=(e,t)=>{We(e.inputs),Ve(e,"ReduceSum",t,(r,a)=>[`var value = ${a.type.storage}(0);`,"",`value += ${r.getByIndices("input_indices")};`,""])},bo=(e,t)=>{We(e.inputs),Ve(e,"ReduceSumSquare",t,(r,a)=>[`var t = ${a.type.value}(0); var value = ${a.type.value}(0);`,"",`t = ${r.getByIndices("input_indices")}; value += t * t;`,""])},Le=(e,t,r)=>{if(t.length===0)return r;let a=1,n=1;for(let i=0;i<t.length;i++)t.indexOf(i)===-1?a*=e[i]:n*=e[i];return n<32&&a>1024},jd=(e,t)=>{Le(e.inputs[0].dims,t.axes,t.noopWithEmptyAxes)?mo(e,t):Dd(e,t)},Kd=(e,t)=>{Le(e.inputs[0].dims,t.axes,t.noopWithEmptyAxes)?po(e,t):Pd(e,t)},Zd=(e,t)=>{Le(e.inputs[0].dims,t.axes,t.noopWithEmptyAxes)?co(e,t):Ud(e,t)},Qd=(e,t)=>{Le(e.inputs[0].dims,t.axes,t.noopWithEmptyAxes)?fo(e,t):qd(e,t)},Xd=(e,t)=>{Le(e.inputs[0].dims,t.axes,t.noopWithEmptyAxes)?ho(e,t):Wd(e,t)},Yd=(e,t)=>{Le(e.inputs[0].dims,t.axes,t.noopWithEmptyAxes)?go(e,t):Vd(e,t)},Jd=(e,t)=>{Le(e.inputs[0].dims,t.axes,t.noopWithEmptyAxes)?_o(e,t):Ld(e,t)},ep=(e,t)=>{Le(e.inputs[0].dims,t.axes,t.noopWithEmptyAxes)?yo(e,t):Gd(e,t)},tp=(e,t)=>{Le(e.inputs[0].dims,t.axes,t.noopWithEmptyAxes)?bo(e,t):Hd(e,t)},rp=(e,t)=>{Le(e.inputs[0].dims,t.axes,t.noopWithEmptyAxes)?lo(e,t):Fd(e,t)}}),Bi,ip,ap,ya,Cm=P(()=>{ee(),ve(),Va(),Bi=e=>{if(!e||e.length===0||e.length>2)throw new Error("ArgMinMaxOp op requires 1 or 2 inputs.");if(e[0].dataType!==1)throw new Error("Invalid input type.")},ip=(e,t)=>{Bi(e.inputs);let r=(a,n,i)=>{let s=[];for(let u=0;u<a.rank;u++)(i.indexOf(u)>=0||i.length===0)&&s.push(`input_indices[${u}] = 0;`);return[`${s.join(`
`)}`,`var value = ${a.getByIndices("input_indices")};
var best_index : i32 = 0;`,`if (${a.getByIndices("input_indices")} ${t.selectLastIndex>0?"<=":"<"} value) {
         value = ${a.getByIndices("input_indices")};
         best_index = i32(last_index);
       }`,"",n.setByOffset("global_idx","best_index")]};e.compute(Ur("ArgMin",{hint:t.cacheKey,inputDependencies:["rank"]},[e.inputs[0]],r,[t.axis],7,t.keepDims),{inputs:[0]})},ap=(e,t)=>{Bi(e.inputs);let r=(a,n,i)=>{let s=[];for(let u=0;u<a.rank;u++)(i.indexOf(u)>=0||i.length===0)&&s.push(`input_indices[${u}] = 0;`);return[`${s.join(`
`)}`,`var value = ${a.getByIndices("input_indices")};
var best_index : i32 = 0;`,`if (${a.getByIndices("input_indices")} ${t.selectLastIndex>0?">=":">"} value) {
         value = ${a.getByIndices("input_indices")};
         best_index = i32(last_index);
       }`,"",n.setByOffset("global_idx","best_index")]};e.compute(Ur("argMax",{hint:t.cacheKey,inputDependencies:["rank"]},[e.inputs[0]],r,[t.axis],7,t.keepDims),{inputs:[0]})},ya=e=>pe(e)}),wo,Tr,$o,vo,xo,ur,ko,np,La=P(()=>{ee(),ae(),qa(),ne(),wo=(e,t)=>{let r=e[0],a=e[1],n=e[2],i=e[3],s=e[4],u=e[5];if(s&&u)throw new Error("Attention cannot have both past and attention_bias");if(r.dims.length!==3)throw new Error('Input "input" must have 3 dimensions');let d=r.dims[0],l=r.dims[1],c=r.dims[2];if(n.dims.length!==1)throw new Error('Input "bias" is expected to have 1 dimensions');if(a.dims.length!==2)throw new Error('Input "weights" is expected to have 2 dimensions');if(a.dims[0]!==c)throw new Error("Input 1 dimension 0 should have same length as dimension 2 of input 0");if(n.dims[0]!==a.dims[1])throw new Error('Input "bias" dimension 0 should have same length as dimension 1 of input "weights"');let f=n.dims[0]/3,m=f,g=m;if(t.qkvHiddenSizes.length>0){if(t.qkvHiddenSizes.length!==3)throw new Error("qkv_hidden_sizes attribute should have 3 elements");for(let S of t.qkvHiddenSizes)if(S%t.numHeads!==0)throw new Error("qkv_hidden_sizes should be divisible by num_heads");f=t.qkvHiddenSizes[0],m=t.qkvHiddenSizes[1],g=t.qkvHiddenSizes[2]}let _=l;if(f!==m)throw new Error("qkv_hidden_sizes first element should be same as the second");if(n.dims[0]!==f+m+g)throw new Error('Input "bias" dimension 0 should have same length as sum of Q/K/V hidden sizes');let b=0;if(s){if(m!==g)throw new Error('Input "past" expect k_hidden_size == v_hidden_size');if(s.dims.length!==5)throw new Error('Input "past" must have 5 dimensions');if(s.dims[0]!==2)throw new Error('Input "past" first dimension must be 2');if(s.dims[1]!==d)throw new Error('Input "past" second dimension must be batch_size');if(s.dims[2]!==t.numHeads)throw new Error('Input "past" third dimension must be num_heads');if(s.dims[4]!==m/t.numHeads)throw new Error('Input "past" fifth dimension must be k_hidden_size / num_heads');t.pastPresentShareBuffer||(b=s.dims[3])}let x=_+b,$=-1,w=0;if(i)throw new Error("Mask not supported");if(s)throw new Error("past is not supported");if(u){if(u.dims.length!==4)throw new Error('Input "attention_bias" must have 4 dimensions');if(u.dims[0]!==d||u.dims[1]!==t.numHeads||u.dims[2]!==l||u.dims[3]!==x)throw new Error('Expect "attention_bias" shape (batch_size, num_heads, sequence_length, total_sequence_length)')}return{batchSize:d,sequenceLength:l,pastSequenceLength:b,kvSequenceLength:_,totalSequenceLength:x,maxSequenceLength:$,inputHiddenSize:c,hiddenSize:f,vHiddenSize:g,headSize:Math.floor(f/t.numHeads),vHeadSize:Math.floor(g/t.numHeads),numHeads:t.numHeads,isUnidirectional:!1,pastPresentShareBuffer:!1,maskFilterValue:t.maskFilterValue,maskType:w,scale:t.scale,broadcastResPosBias:!1,passPastInKv:!1,qkvFormat:1}},Tr=(e,t,r)=>t&&e?`
      let total_sequence_length_input = u32(${t.getByOffset("0")});
      let present_sequence_length = max(total_sequence_length_input, uniforms.past_sequence_length);
      let is_subsequent_prompt: bool = sequence_length > 1 && sequence_length != total_sequence_length_input;
      let is_first_prompt: bool = is_subsequent_prompt == false && sequence_length == total_sequence_length_input;
      total_sequence_length = u32(${e==null?void 0:e.getByOffset("batchIdx")}) + 1;
      var past_sequence_length: u32 = 0;
      if (is_first_prompt == false) {
        past_sequence_length = total_sequence_length - sequence_length;
      }
       `:`
    ${r?"let past_sequence_length = uniforms.past_sequence_length":""};
    let present_sequence_length = total_sequence_length;
    `,$o=(e,t,r,a,n,i,s,u)=>{let d=$e(s?1:i),l=64,c=i/d;c<l&&(l=32);let f=Math.ceil(i/d/l),m=[{type:12,data:t},{type:12,data:r},{type:12,data:a},{type:12,data:n},{type:12,data:c},{type:12,data:f}],g=ke(e.dataType,d),_=Ee(1,d),b=["type"];s&&b.push("type"),u&&b.push("type");let x=$=>{let w=H("x",e.dataType,e.dims,d),S=[w],k=s?R("seq_lens",s.dataType,s.dims):void 0;k&&S.push(k);let T=u?R("total_sequence_length_input",u.dataType,u.dims):void 0;T&&S.push(T);let E=Ee(e.dataType),z=[{name:"batch_size",type:"u32"},{name:"num_heads",type:"u32"},{name:"past_sequence_length",type:"u32"},{name:"sequence_length",type:"u32"},{name:"total_sequence_length",type:"u32"},{name:"elements_per_thread",type:"u32"}];return`
  var<workgroup> thread_max: array<f32, ${l}>;
  var<workgroup> thread_sum: array<f32, ${l}>;
  ${$.registerUniforms(z).declareVariables(...S)}
  ${$.mainStart([l,1,1])}
    let batchIdx = workgroup_id.z / uniforms.num_heads;
    let headIdx = workgroup_id.z % uniforms.num_heads;
    let sequence_length = uniforms.sequence_length;
    var total_sequence_length = uniforms.total_sequence_length;
    ${Tr(k,T,!1)}
    let local_offset = local_idx * uniforms.elements_per_thread;
    let offset = (global_idx / ${l}) * uniforms.total_sequence_length + local_offset;
    let seq_causal_length = ${s?"u32(past_sequence_length + workgroup_id.y + 1)":"total_sequence_length"};
    var thread_max_vector = ${_}(-3.402823e+38f);
    for (var i: u32 = 0; i < uniforms.elements_per_thread && i + local_offset < seq_causal_length; i++) {
      thread_max_vector = max(${_}(x[offset + i]), thread_max_vector);
    }
    thread_max[local_idx] = ${(()=>{switch(d){case 1:return"thread_max_vector";case 2:return"max(thread_max_vector.x, thread_max_vector.y)";case 4:return"max(max(thread_max_vector.x, thread_max_vector.y), max(thread_max_vector.z, thread_max_vector.w))";default:throw new Error(`Unsupported components: ${d}`)}})()};
    workgroupBarrier();

    var max_value =  f32(-3.402823e+38f);
    for (var i = 0u; i < ${l}; i++) {
      max_value = max(thread_max[i], max_value);
    }

    var sum_vector = ${_}(0);
    for (var i: u32 = 0; i < uniforms.elements_per_thread && i + local_offset < seq_causal_length; i++) {
      sum_vector += exp(${_}(x[offset + i]) - max_value);
    }
    thread_sum[local_idx] = ${(()=>{switch(d){case 1:return"sum_vector";case 2:return"sum_vector.x + sum_vector.y";case 4:return"sum_vector.x + sum_vector.y + sum_vector.z + sum_vector.w";default:throw new Error(`Unsupported components: ${d}`)}})()};
    workgroupBarrier();

    var sum: f32 = 0;
    for (var i = 0u; i < ${l}; i++) {
      sum += thread_sum[i];
    }

    if (sum == 0) {
      for (var i: u32 = 0; i < uniforms.elements_per_thread && i + local_offset < seq_causal_length; i++) {
        x[offset + i] = ${w.type.value}(${E}(1.0) / ${E}(seq_causal_length));
      }
    } else {
      for (var i: u32 = 0; i < uniforms.elements_per_thread && i + local_offset < seq_causal_length; i++) {
        var f32input = ${_}(x[offset + i]);
        x[offset + i] = ${w.type.value}(exp(f32input - max_value) / sum);
      }
    }
      ${s?`
        for (var total_seq_id: u32 = seq_causal_length; total_seq_id + local_offset < uniforms.total_sequence_length; total_seq_id++) {
          x[offset + total_seq_id] = ${w.type.value}(${E}(0));
        }`:""};
  }`};return{name:"AttentionProbsSoftmax",shaderCache:{hint:`${l};${g};${d}`,inputDependencies:b},getShaderSource:x,getRunData:()=>({outputs:[],dispatchGroup:{x:1,y:n,z:t*r},programUniforms:m})}},vo=(e,t,r,a,n,i,s,u,d)=>{let l=s+i.kvSequenceLength,c=[i.batchSize,i.numHeads,i.sequenceLength,l],f=e>1&&a,m=i.kvNumHeads?i.kvNumHeads:i.numHeads,g=f?[i.batchSize,m,l,i.headSize]:void 0,_=i.nReps?i.nReps:1,b=i.scale===0?1/Math.sqrt(i.headSize):i.scale,x=$e(i.headSize),$=i.headSize/x,w=12,S={x:Math.ceil(l/w),y:Math.ceil(i.sequenceLength/w),z:i.batchSize*i.numHeads},k=[{type:12,data:i.sequenceLength},{type:12,data:$},{type:12,data:l},{type:12,data:i.numHeads},{type:12,data:i.headSize},{type:1,data:b},{type:12,data:s},{type:12,data:i.kvSequenceLength},{type:12,data:_}],T=f&&a&&O.size(a.dims)>0,E=["type","type"];T&&E.push("type"),n&&E.push("type"),u&&E.push("type"),d&&E.push("type");let z=[{dims:c,dataType:t.dataType,gpuDataType:0}];f&&z.push({dims:g,dataType:t.dataType,gpuDataType:0});let C=A=>{let q=R("q",t.dataType,t.dims,x),X=R("key",r.dataType,r.dims,x),G=[q,X];if(T){let Y=R("past_key",a.dataType,a.dims,x);G.push(Y)}n&&G.push(R("attention_bias",n.dataType,n.dims));let Z=u?R("seq_lens",u.dataType,u.dims):void 0;Z&&G.push(Z);let oe=d?R("total_sequence_length_input",d.dataType,d.dims):void 0;oe&&G.push(oe);let re=H("output",t.dataType,c),L=[re];f&&L.push(H("present_key",t.dataType,g,x));let ie=Ee(1,x),F=[{name:"M",type:"u32"},{name:"K",type:"u32"},{name:"N",type:"u32"},{name:"num_heads",type:"u32"},{name:"head_size",type:"u32"},{name:"alpha",type:"f32"},{name:"past_sequence_length",type:"u32"},{name:"kv_sequence_length",type:"u32"},{name:"n_reps",type:"u32"}];return`
  const TILE_SIZE = ${w}u;

  var<workgroup> tileQ: array<${q.type.storage}, ${w*w}>;
  var<workgroup> tileK: array<${q.type.storage}, ${w*w}>;
  ${A.registerUniforms(F).declareVariables(...G,...L)}
  ${A.mainStart([w,w,1])}
    // x holds the N and y holds the M
    let headIdx = workgroup_id.z % uniforms.num_heads;
    let kvHeadIdx = ${_===1?"headIdx":"headIdx / uniforms.n_reps"};
    let kv_num_heads = ${_===1?"uniforms.num_heads":"uniforms.num_heads / uniforms.n_reps"};
    let batchIdx = workgroup_id.z / uniforms.num_heads;
    let m = workgroup_id.y * TILE_SIZE;
    let n = workgroup_id.x * TILE_SIZE;
    let sequence_length = uniforms.M;
    var total_sequence_length = uniforms.N;
    ${Tr(Z,oe,!0)}
    let absKvHeadIdx = batchIdx * kv_num_heads + kvHeadIdx;
    let qOffset = workgroup_id.z * uniforms.M * uniforms.K + m * uniforms.K;
    ${T&&f?"let pastKeyOffset = absKvHeadIdx * uniforms.past_sequence_length * uniforms.K;":""};
    let kOffset = absKvHeadIdx * uniforms.kv_sequence_length * uniforms.K;
    ${f?"let presentKeyOffset = absKvHeadIdx * uniforms.N * uniforms.K;":""}
    var value = ${ie}(0);
    for (var w: u32 = 0u; w < uniforms.K; w += TILE_SIZE) {
      if (global_id.y < uniforms.M && w + local_id.x < uniforms.K) {
        tileQ[TILE_SIZE * local_id.y + local_id.x] = q[qOffset + local_id.y * uniforms.K + w + local_id.x];
      }
      if (n + local_id.y < uniforms.N && w + local_id.x < uniforms.K) {
        var idx = TILE_SIZE * local_id.y + local_id.x;
      ${T&&f?`
              if (n + local_id.y < past_sequence_length) {
                tileK[idx] = past_key[pastKeyOffset + (n + local_id.y) * uniforms.K + w + local_id.x];
              } else if (n + local_id.y - past_sequence_length < uniforms.kv_sequence_length) {
                tileK[idx] = key[kOffset + (n + local_id.y - past_sequence_length) * uniforms.K + w + local_id.x];
              }`:`
          if (n + local_id.y < uniforms.kv_sequence_length) {
            tileK[idx] = key[kOffset + (n + local_id.y) * uniforms.K + w + local_id.x];
          }`}
      ${f?`if (n + local_id.y < present_sequence_length) {
        present_key[presentKeyOffset + (n + local_id.y) * uniforms.K + w + local_id.x] = tileK[idx];
      }`:""}
      }
      workgroupBarrier();

      for (var k: u32 = 0u; k < TILE_SIZE && w+k < uniforms.K; k++) {
          value += ${ie}(tileQ[TILE_SIZE * local_id.y + k] * tileK[TILE_SIZE * local_id.x + k]);
      }

      workgroupBarrier();
    }

    if (global_id.y < uniforms.M && global_id.x < total_sequence_length) {
      let headOffset = workgroup_id.z * uniforms.M * uniforms.N;
      let outputIdx = headOffset + global_id.y * uniforms.N + global_id.x;
      var sum: f32 = ${(()=>{switch(x){case 1:return"value";case 2:return"value.x + value.y";case 4:return"value.x + value.y + value.z + value.w";default:throw new Error(`Unsupported components: ${x}`)}})()};
        output[outputIdx] = ${re.type.value} (sum * uniforms.alpha) + ${n?"attention_bias[outputIdx]":"0.0"};
    }
  }`};return{name:"AttentionProbs",shaderCache:{hint:`${x};${n!==void 0};${a!==void 0};${e}`,inputDependencies:E},getRunData:()=>({outputs:z,dispatchGroup:S,programUniforms:k}),getShaderSource:C}},xo=(e,t,r,a,n,i,s=void 0,u=void 0)=>{let d=i+n.kvSequenceLength,l=n.nReps?n.nReps:1,c=n.vHiddenSize*l,f=e>1&&a,m=n.kvNumHeads?n.kvNumHeads:n.numHeads,g=f?[n.batchSize,m,d,n.headSize]:void 0,_=[n.batchSize,n.sequenceLength,c],b=12,x={x:Math.ceil(n.vHeadSize/b),y:Math.ceil(n.sequenceLength/b),z:n.batchSize*n.numHeads},$=[{type:12,data:n.sequenceLength},{type:12,data:d},{type:12,data:n.vHeadSize},{type:12,data:n.numHeads},{type:12,data:n.headSize},{type:12,data:c},{type:12,data:i},{type:12,data:n.kvSequenceLength},{type:12,data:l}],w=f&&a&&O.size(a.dims)>0,S=["type","type"];w&&S.push("type"),s&&S.push("type"),u&&S.push("type");let k=[{dims:_,dataType:t.dataType,gpuDataType:0}];f&&k.push({dims:g,dataType:t.dataType,gpuDataType:0});let T=E=>{let z=R("probs",t.dataType,t.dims),C=R("v",r.dataType,r.dims),A=[z,C];w&&A.push(R("past_value",a.dataType,a.dims));let q=s?R("seq_lens",s.dataType,s.dims):void 0;s&&A.push(q);let X=u?R("total_sequence_length_input",u.dataType,u.dims):void 0;u&&A.push(X);let G=[H("output",t.dataType,_)];f&&G.push(H("present_value",t.dataType,g));let Z=[{name:"M",type:"u32"},{name:"K",type:"u32"},{name:"N",type:"u32"},{name:"num_heads",type:"u32"},{name:"head_size",type:"u32"},{name:"v_hidden_size",type:"u32"},{name:"past_sequence_length",type:"u32"},{name:"kv_sequence_length",type:"u32"},{name:"n_reps",type:"u32"}];return`
  const TILE_SIZE = ${b}u;
  var<workgroup> tileQ: array<${z.type.value}, ${b*b}>;
  var<workgroup> tileV: array<${z.type.value}, ${b*b}>;
  ${E.registerUniforms(Z).declareVariables(...A,...G)}
  ${E.mainStart([b,b,1])}
   let headIdx = workgroup_id.z % uniforms.num_heads;
   let batchIdx = workgroup_id.z / uniforms.num_heads;
   let kvHeadIdx = ${l===1?"headIdx":"headIdx / uniforms.n_reps"};
   let kv_num_heads = ${l===1?"uniforms.num_heads":"uniforms.num_heads / uniforms.n_reps"};
   let m = global_id.y;
   let n = global_id.x;
   let sequence_length = uniforms.M;
   var total_sequence_length = uniforms.K;
   ${Tr(q,X,!0)}
   let offsetA = workgroup_id.z * uniforms.M * uniforms.K + m * uniforms.K;
   let absKvHeadIdx = batchIdx * kv_num_heads + kvHeadIdx; // kvHeadIdx is relative to the batch
   ${w&&f?"let pastValueOffset = absKvHeadIdx * uniforms.N * uniforms.past_sequence_length + n;":""};
   let vOffset = absKvHeadIdx * uniforms.N * uniforms.kv_sequence_length + n;
   ${f?"let presentValueOffset = absKvHeadIdx * uniforms.N * uniforms.K + n;":""}
   var value = ${z.type.storage}(0);
   for (var w: u32 = 0u; w < uniforms.K; w += TILE_SIZE) {
      if (m < uniforms.M && w + local_id.x < uniforms.K) {
        tileQ[TILE_SIZE * local_id.y + local_id.x] = probs[offsetA + w + local_id.x];
      }
      if (n < uniforms.N && w + local_id.y < uniforms.K) {
        var idx = TILE_SIZE * local_id.y + local_id.x;
        ${w&&f?`
        if (w + local_id.y < past_sequence_length) {
          tileV[idx] = past_value[pastValueOffset + (w + local_id.y) * uniforms.N];
        } else if (w + local_id.y - past_sequence_length < uniforms.kv_sequence_length) {
          tileV[idx] = v[vOffset + (w + local_id.y - past_sequence_length) * uniforms.N];
        }
      `:`
            if (w + local_id.y < uniforms.kv_sequence_length) {
              tileV[idx] = v[vOffset + (w + local_id.y) * uniforms.N];
            }`}
        ${f?`
            if (w + local_id.y < present_sequence_length) {
          present_value[presentValueOffset + (w + local_id.y) * uniforms.N] = tileV[idx];
        }`:""}
      }
     workgroupBarrier();
     for (var k: u32 = 0u; k < TILE_SIZE && w+k < total_sequence_length; k++) {
       value += tileQ[TILE_SIZE * local_id.y + k] * tileV[TILE_SIZE * k + local_id.x];
     }
     workgroupBarrier();
   }

   // we need to transpose output from BNSH_v to BSND_v
   if (m < uniforms.M && n < uniforms.N) {
     let outputIdx = batchIdx * uniforms.M * uniforms.v_hidden_size + m * uniforms.v_hidden_size
       + headIdx * uniforms.N + n;
     output[outputIdx] = value;
   }
  }`};return{name:"AttentionScore",shaderCache:{hint:`${a!==void 0};${e}`,inputDependencies:S},getRunData:()=>({outputs:k,dispatchGroup:x,programUniforms:$}),getShaderSource:T}},ur=(e,t,r,a,n,i,s,u,d,l,c=void 0,f=void 0)=>{let m=Math.min(e.outputCount,1+(s?1:0)+(u?1:0)),g=m>1?l.pastSequenceLength:0,_=g+l.kvSequenceLength,b=d&&O.size(d.dims)>0?d:void 0,x=[t,r];m>1&&s&&O.size(s.dims)>0&&x.push(s),b&&x.push(b),c&&x.push(c),f&&x.push(f);let $=e.compute(vo(m,t,r,s,b,l,g,c,f),{inputs:x,outputs:m>1?[-1,1]:[-1]})[0];e.compute($o($,l.batchSize,l.numHeads,g,l.sequenceLength,_,c,f),{inputs:c&&f?[$,c,f]:[$],outputs:[]});let w=[$,a];m>1&&u&&O.size(u.dims)>0&&w.push(u),c&&w.push(c),f&&w.push(f),e.compute(xo(m,$,a,u,l,g,c,f),{inputs:w,outputs:m>1?[0,2]:[0]})},ko=(e,t)=>{let r=[t.batchSize,t.numHeads,t.sequenceLength,t.headSize],a=t.sequenceLength,n=t.inputHiddenSize,i=t.headSize,s=12,u={x:Math.ceil(t.headSize/s),y:Math.ceil(t.sequenceLength/s),z:t.batchSize*t.numHeads},d=[e.inputs[0],e.inputs[1],e.inputs[2]],l=[{type:12,data:a},{type:12,data:n},{type:12,data:i},{type:12,data:t.numHeads},{type:12,data:t.headSize},{type:12,data:t.hiddenSize},{type:12,data:t.hiddenSize+t.hiddenSize+t.vHiddenSize}],c=f=>{let m=H("output_q",d[0].dataType,r),g=H("output_k",d[0].dataType,r),_=H("output_v",d[0].dataType,r),b=R("input",d[0].dataType,d[0].dims),x=R("weight",d[1].dataType,d[1].dims),$=R("bias",d[2].dataType,d[2].dims),w=b.type.storage,S=[{name:"M",type:"u32"},{name:"K",type:"u32"},{name:"N",type:"u32"},{name:"num_heads",type:"u32"},{name:"head_size",type:"u32"},{name:"hidden_size",type:"u32"},{name:"ldb",type:"u32"}];return`
  const TILE_SIZE = ${s}u;
  var<workgroup> tileInput: array<${w}, ${s*s}>;
  var<workgroup> tileWeightQ: array<${w}, ${s*s}>;
  var<workgroup> tileWeightK: array<${w}, ${s*s}>;
  var<workgroup> tileWeightV: array<${w}, ${s*s}>;
  ${f.registerUniforms(S).declareVariables(b,x,$,m,g,_)}
  ${f.mainStart([s,s,1])}
    let batchIndex = workgroup_id.z / uniforms.num_heads;
    let headNumber = workgroup_id.z % uniforms.num_heads;
    let m = global_id.y;
    let n = global_id.x;

    let inputOffset = batchIndex * (uniforms.M * uniforms.K) + m * uniforms.K;
    let biasOffsetQ = headNumber * uniforms.head_size;
    let biasOffsetK = uniforms.hidden_size + biasOffsetQ;
    let biasOffsetV = uniforms.hidden_size + biasOffsetK;

    var valueQ = ${w}(0);
    var valueK = ${w}(0);
    var valueV = ${w}(0);
    for (var w: u32 = 0u; w < uniforms.K; w += TILE_SIZE) {
      if (m < uniforms.M && w + local_id.x < uniforms.K) {
        tileInput[TILE_SIZE * local_id.y + local_id.x] = input[inputOffset + w + local_id.x];
      }
      if (n < uniforms.N && w + local_id.y < uniforms.K) {
        let offset = n + (w + local_id.y) * uniforms.ldb;
        tileWeightQ[TILE_SIZE * local_id.y + local_id.x] = weight[biasOffsetQ + offset];
        tileWeightK[TILE_SIZE * local_id.y + local_id.x] = weight[biasOffsetK + offset];
        tileWeightV[TILE_SIZE * local_id.y + local_id.x] = weight[biasOffsetV + offset];
      }
      workgroupBarrier();
      for (var k: u32 = 0u; k<TILE_SIZE && w+k < uniforms.K; k++) {
        let inputTileOffset = TILE_SIZE * local_id.y + k;
        let weightTileOffset = TILE_SIZE * k + local_id.x;
        valueQ += tileInput[inputTileOffset] * tileWeightQ[weightTileOffset];
        valueK += tileInput[inputTileOffset] * tileWeightK[weightTileOffset];
        valueV += tileInput[inputTileOffset] * tileWeightV[weightTileOffset];
      }

      workgroupBarrier();
    }

    let headOffset = (m * uniforms.N + n) % uniforms.head_size;
    valueQ += bias[headOffset + biasOffsetQ];
    valueK += bias[headOffset + biasOffsetK];
    valueV += bias[headOffset + biasOffsetV];

    let offset = workgroup_id.z * uniforms.M * uniforms.N;
    if (m < uniforms.M && n < uniforms.N) {
      let outputIdx = offset + m * uniforms.N + n;
      output_q[outputIdx] = valueQ;
      output_k[outputIdx] = valueK;
      output_v[outputIdx] = valueV;
    }
  }`};return e.compute({name:"AttentionPrepare",shaderCache:{inputDependencies:["type","type","type"]},getRunData:()=>({outputs:[{dims:r,dataType:e.inputs[0].dataType,gpuDataType:0},{dims:r,dataType:e.inputs[0].dataType,gpuDataType:0},{dims:r,dataType:e.inputs[0].dataType,gpuDataType:0}],dispatchGroup:u,programUniforms:l}),getShaderSource:c},{inputs:d,outputs:[-1,-1,-1]})},np=(e,t)=>{let r=wo(e.inputs,t),[a,n,i]=ko(e,r);return ur(e,a,n,i,e.inputs[4],void 0,void 0,void 0,e.inputs[5],r)}}),So,To,Io,sp,Om=P(()=>{je(),ee(),ae(),ve(),ne(),So=(e,t)=>{if(!e||e.length!==5)throw new Error("BatchNormalization requires 5 inputs");let r=(a,n,i)=>{let s=n.length;if(s!==a.length)throw new Error(`${i}: num dimensions != ${s}`);n.forEach((u,d)=>{if(u!==a[d])throw new Error(`${i}: dim[${d}] do not match`)})};if(e[0].dims.length>1){let a=t.format==="NHWC"?t.spatial?e[0].dims.slice(-1):e[0].dims.slice(-1).concat(e[0].dims.slice(1,e[0].dims.length-1)):e[0].dims.slice(1,t.spatial?2:void 0);r(e[1].dims,a,"Invalid input scale"),r(e[2].dims,a,"Invalid input B"),r(e[3].dims,a,"Invalid input mean"),r(e[4].dims,a,"Invalid input var")}else r(e[1].dims,[1],"Invalid input scale"),r(e[2].dims,[1],"Invalid input B"),r(e[3].dims,[1],"Invalid input mean"),r(e[4].dims,[1],"Invalid input var")},To=(e,t)=>{let{epsilon:r,spatial:a,format:n}=t,i=e[0].dims,s=a?$e(i[i.length-1]):1,u=n==="NHWC"&&i.length>1?s:1,d=O.size(i)/s,l=a,c=l?i.length:i,f=R("x",e[0].dataType,e[0].dims,s),m=R("scale",e[1].dataType,e[1].dims,u),g=R("bias",e[2].dataType,e[2].dims,u),_=R("inputMean",e[3].dataType,e[3].dims,u),b=R("inputVar",e[4].dataType,e[4].dims,u),x=H("y",e[0].dataType,c,s),$=()=>{let S="";if(a)S=`let cOffset = ${i.length===1?"0u":n==="NHWC"?`outputIndices[${i.length-1}] / ${s}`:"outputIndices[1]"};`;else if(n==="NCHW")S=`
            ${x.indicesSet("outputIndices","0","0")}
            let cOffset = ${x.indicesToOffset("outputIndices")};`;else{S=`var cIndices = ${m.type.indices}(0);
                       cIndices[0] = outputIndices[${i.length-1}];`;for(let k=1;k<m.rank;k++)S+=`cIndices[${k}] = outputIndices[${k}];`;S+=`let cOffset = ${m.indicesToOffset("cIndices")};`}return S},w=S=>`
  const epsilon = ${r};
  ${S.registerUniform("outputSize","u32").declareVariables(f,m,g,_,b,x)}
  ${S.mainStart()}
  ${S.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.outputSize")}
    var outputIndices = ${x.offsetToIndices(`global_idx * ${s}`)};
    ${$()}
    let scale = ${m.getByOffset("cOffset")};
    let bias = ${g.getByOffset("cOffset")};
    let inputMean = ${_.getByOffset("cOffset")};
    let inputVar = ${b.getByOffset("cOffset")};
    let x = ${f.getByOffset("global_idx")};
    let value = (x - inputMean) * inverseSqrt(inputVar + epsilon) * scale + bias;
    ${x.setByOffset("global_idx","value")}
  }`;return{name:"BatchNormalization",shaderCache:{hint:`${t.epsilon}_${t.format}_${a}_${s}`,inputDependencies:l?["rank","type","type","type","type"]:void 0},getShaderSource:w,getRunData:()=>({outputs:[{dims:e[0].dims,dataType:e[0].dataType}],dispatchGroup:{x:Math.ceil(d/64)},programUniforms:l?[{type:12,data:d},...Q(i)]:[{type:12,data:d}]})}},Io=e=>pe(e),sp=(e,t)=>{let{inputs:r,outputCount:a}=e,n=Io({...t,outputCount:a});if(_e.webgpu.validateInputContent&&So(r,n),t.trainingMode)throw new Error("BatchNormalization trainingMode is not supported yet.");e.compute(To(r,n))}}),Eo,zo,op,Am=P(()=>{ae(),ne(),Eo=e=>{if(e[0].dims.length!==3)throw new Error("input should have 3 dimensions");if(![320,640,1280].includes(e[0].dims[2]))throw new Error("number of channels should be 320, 640 or 1280");if(e[1].dims.length!==1)throw new Error("bias is expected to have 1 dimensions");if(e[0].dims[2]!==e[1].dims[0])throw new Error("last dimension of input and bias are not the same")},zo=e=>{let t=e[0].dims,r=e[0].dims[2],a=O.size(t)/4,n=e[0].dataType,i=R("input",n,t,4),s=R("bias",n,[r],4),u=R("residual",n,t,4),d=H("output",n,t,4);return{name:"BiasAdd",getRunData:()=>({outputs:[{dims:t,dataType:e[0].dataType}],dispatchGroup:{x:Math.ceil(a/64)}}),getShaderSource:l=>`
  const channels = ${r}u / 4;
  ${l.declareVariables(i,s,u,d)}

  ${l.mainStart()}
    ${l.guardAgainstOutOfBoundsWorkgroupSizes(a)}
    let value = ${i.getByOffset("global_idx")}
      + ${s.getByOffset("global_idx % channels")} + ${u.getByOffset("global_idx")};
    ${d.setByOffset("global_idx","value")}
  }`}},op=e=>{Eo(e.inputs),e.compute(zo(e.inputs))}}),Co,de,up,lp,dp,pp,cp,fp,hp,mp,gp,Oo,_p,yp,bp,wp,ir,$p,Rr,vp,xp,kp,Sp,Tp,Ip,Ep,zp,Cp,Op,Ap,Bp,Rp,Np,Mp,Dp,Ri,Pp,ba,wa,Up,qp,Wp,Ao,Bo,Vp,Ga=P(()=>{ee(),ae(),ve(),ne(),Co=(e,t,r,a,n,i,s)=>{let u=Math.ceil(t/4),d="";typeof n=="string"?d=`${n}(a)`:d=n("a");let l=R("inputData",r,[u],4),c=H("outputData",a,[u],4),f=[{name:"vec_size",type:"u32"}];return s&&f.push(...s),`
      ${e.registerUniforms(f).declareVariables(l,c)}

  ${i??""}

  ${e.mainStart()}
    ${e.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.vec_size")}

    let a = ${l.getByOffset("global_idx")};
    ${c.setByOffset("global_idx",d)}
  }`},de=(e,t,r,a,n,i=e.dataType,s,u)=>{let d=[{type:12,data:Math.ceil(O.size(e.dims)/4)}];return s&&d.push(...s),{name:t,shaderCache:{hint:n,inputDependencies:["type"]},getShaderSource:l=>Co(l,O.size(e.dims),e.dataType,i,r,a,u),getRunData:l=>({outputs:[{dims:e.dims,dataType:i}],dispatchGroup:{x:Math.ceil(O.size(l[0].dims)/64/4)},programUniforms:d})}},up=e=>{e.compute(de(e.inputs[0],"Abs","abs"))},lp=e=>{e.compute(de(e.inputs[0],"Acos","acos"))},dp=e=>{e.compute(de(e.inputs[0],"Acosh","acosh"))},pp=e=>{e.compute(de(e.inputs[0],"Asin","asin"))},cp=e=>{e.compute(de(e.inputs[0],"Asinh","asinh"))},fp=e=>{e.compute(de(e.inputs[0],"Atan","atan"))},hp=e=>{e.compute(de(e.inputs[0],"Atanh","atanh"))},mp=e=>pe(e),gp=(e,t)=>{let r;switch(t.to){case 10:r="vec4<f16>";break;case 1:r="vec4<f32>";break;case 12:r="vec4<u32>";break;case 6:r="vec4<i32>";break;case 9:r="vec4<bool>";break;default:throw new RangeError(`not supported type (specified in attribute 'to' from 'Cast' operator): ${t.to}`)}e.compute(de(e.inputs[0],"Cast",r,void 0,t.cacheKey,t.to))},Oo=e=>{let t,r,a=e.length>=2&&e[1].data!==0,n=e.length>=3&&e[2].data!==0;switch(e[0].dataType){case 1:t=a?e[1].getFloat32Array()[0]:-34028234663852886e22,r=n?e[2].getFloat32Array()[0]:34028234663852886e22;break;case 10:t=a?e[1].getUint16Array()[0]:64511,r=n?e[2].getUint16Array()[0]:31743;break;default:throw new Error("Unsupport data type")}return pe({min:t,max:r})},_p=(e,t)=>{let r=t||Oo(e.inputs),a=Ee(e.inputs[0].dataType);e.compute(de(e.inputs[0],"Clip",n=>`clamp(${n}, vec4<${a}>(uniforms.min), vec4<${a}>(uniforms.max))`,void 0,r.cacheKey,void 0,[{type:e.inputs[0].dataType,data:r.min},{type:e.inputs[0].dataType,data:r.max}],[{name:"min",type:a},{name:"max",type:a}]),{inputs:[0]})},yp=e=>{e.compute(de(e.inputs[0],"Ceil","ceil"))},bp=e=>{e.compute(de(e.inputs[0],"Cos","cos"))},wp=e=>{e.compute(de(e.inputs[0],"Cosh","cosh"))},ir=e=>pe(e),$p=(e,t)=>{let r=Ee(e.inputs[0].dataType);e.compute(de(e.inputs[0],"Elu",a=>`elu_vf32(${a})`,`
  const elu_alpha_ = ${r}(${t.alpha});

  fn elu_f32(a: ${r}) -> ${r} {
  return select((exp(a) - 1.0) * elu_alpha_, a, a >= 0.0);
  }

  fn elu_vf32(v: vec4<${r}>) -> vec4<${r}> {
  return vec4(elu_f32(v.x), elu_f32(v.y), elu_f32(v.z), elu_f32(v.w));
  }`,t.cacheKey))},Rr=(e="f32")=>`
const r0: ${e} = 0.3275911;
const r1: ${e} = 0.254829592;
const r2: ${e} = -0.284496736;
const r3: ${e} = 1.421413741;
const r4: ${e} = -1.453152027;
const r5: ${e} = 1.061405429;

fn erf_vf32(v: vec4<${e}>) -> vec4<${e}> {
  let absv = abs(v);
  let x = 1.0 / (1.0 + r0 * absv);
  return sign(v) * (1.0 - ((((r5 * x + r4) * x + r3) * x + r2) * x + r1) * x * exp(-absv * absv));
}`,vp=e=>{let t=Ee(e.inputs[0].dataType);e.compute(de(e.inputs[0],"Erf",r=>`erf_vf32(${r})`,Rr(t)))},xp=e=>{e.compute(de(e.inputs[0],"Exp","exp"))},kp=e=>{e.compute(de(e.inputs[0],"Floor","floor"))},Sp=e=>{let t=Ee(e.inputs[0].dataType);e.compute(de(e.inputs[0],"Gelu",r=>`0.5 * ${r} * (1.0 + erf_vf32(${r} * 0.7071067811865475))`,Rr(t)))},Tp=(e,t)=>{let r=Ee(e.inputs[0].dataType);e.compute(de(e.inputs[0],"LeakyRelu",a=>`select(leaky_relu_alpha_ * ${a}, ${a}, ${a} >= vec4<${r}>(0.0))`,`const leaky_relu_alpha_ = ${r}(${t.alpha});`,t.cacheKey))},Ip=e=>{e.compute(de(e.inputs[0],"Not",t=>`!${t}`))},Ep=e=>{e.compute(de(e.inputs[0],"Neg",t=>`-${t}`))},zp=e=>{e.compute(de(e.inputs[0],"Reciprocal",t=>`1.0/${t}`))},Cp=e=>{let t=Ee(e.inputs[0].dataType);e.compute(de(e.inputs[0],"Relu",r=>`select(vec4<${t}>(0.0), ${r}, ${r} > vec4<${t}>(0.0))`))},Op=e=>{e.compute(de(e.inputs[0],"Sigmoid",t=>`(1.0 / (1.0 + exp(-${t})))`))},Ap=e=>pe(e),Bp=(e,t)=>{let r=Ee(e.inputs[0].dataType);e.compute(de(e.inputs[0],"HardSigmoid",a=>`max(vec4<${r}>(0.0), min(vec4<${r}>(1.0), ${t.alpha} * ${a} + vec4<${r}>(${t.beta})))`,void 0,t.cacheKey))},Rp=e=>{e.compute(de(e.inputs[0],"Sin","sin"))},Np=e=>{e.compute(de(e.inputs[0],"Sinh","sinh"))},Mp=e=>{e.compute(de(e.inputs[0],"Sqrt","sqrt"))},Dp=e=>{e.compute(de(e.inputs[0],"Tan","tan"))},Ri=e=>`sign(${e}) * (1 - exp(-2 * abs(${e}))) / (1 + exp(-2 * abs(${e})))`,Pp=e=>{e.compute(de(e.inputs[0],"Tanh",Ri))},ba=(e="f32")=>`
const fast_gelu_a: ${e} = 0.5;
const fast_gelu_b: ${e} = 0.7978845608028654;
const fast_gelu_c: ${e} = 0.035677408136300125;

fn tanh_v(v: vec4<${e}>) -> vec4<${e}> {
  return ${Ri("v")};
}
`,wa=e=>`(fast_gelu_a + fast_gelu_a * tanh_v(${e} * (fast_gelu_c * ${e} * ${e} + fast_gelu_b))) * ${e}`,Up=e=>{let t=Ee(e.inputs[0].dataType);e.compute(de(e.inputs[0],"FastGelu",wa,ba(t),void 0,e.inputs[0].dataType))},qp=(e,t)=>{let r=Ee(e.inputs[0].dataType);return e.compute(de(e.inputs[0],"ThresholdedRelu",a=>`select(vec4<${r}>(0.0), ${a}, ${a} > thresholded_relu_alpha_)`,`const thresholded_relu_alpha_ = vec4<${r}>(${t.alpha});`,t.cacheKey)),0},Wp=e=>{e.compute(de(e.inputs[0],"Log","log"))},Ao=(e,t)=>`
const alpha = vec4<${e}>(${t});
const one = ${e}(1.0);
const zero = ${e}(0.0);

fn quick_gelu_impl(x: vec4<${e}>) -> vec4<${e}> {
  let v = x *alpha;
  var x1 : vec4<${e}>;
  for (var i = 0; i < 4; i = i + 1) {
    if (v[i] >= zero) {
      x1[i] = one / (one + exp(-v[i]));
    } else {
      x1[i] = one - one / (one + exp(v[i]));
    }
  }
  return x * x1;
}
`,Bo=e=>`quick_gelu_impl(${e})`,Vp=(e,t)=>{let r=Ee(e.inputs[0].dataType);e.compute(de(e.inputs[0],"QuickGelu",Bo,Ao(r,t.alpha),t.cacheKey,e.inputs[0].dataType))}}),Ro,No,Lp,Bm=P(()=>{ae(),ne(),Ga(),Ro=e=>{if(e[0].dims.length!==3)throw new Error("input should have 3 dimensions");if(![2560,5120,10240].includes(e[0].dims[2]))throw new Error("hidden state should be 2560, 5120 or 10240");if(e[1].dims.length!==1)throw new Error("bias is expected to have 1 dimensions");if(e[0].dims[2]!==e[1].dims[0])throw new Error("last dimension of input and bias are not the same")},No=e=>{let t=e[0].dims.slice();t[2]=t[2]/2;let r=R("input",e[0].dataType,e[0].dims,4),a=R("bias",e[0].dataType,[e[0].dims[2]],4),n=H("output",e[0].dataType,t,4),i=O.size(t)/4,s=ke(e[0].dataType);return{name:"BiasSplitGelu",getRunData:()=>({outputs:[{dims:t,dataType:e[0].dataType}],dispatchGroup:{x:Math.ceil(i/64)}}),getShaderSource:u=>`
  const M_SQRT2 = sqrt(2.0);
  const halfChannels = ${e[0].dims[2]/4/2}u;

  ${u.declareVariables(r,a,n)}

  ${Rr(s)}

  ${u.mainStart()}
    ${u.guardAgainstOutOfBoundsWorkgroupSizes(i)}
    let biasIdx = global_idx % halfChannels;
    let batchIndex = global_idx / halfChannels;
    let inputOffset = biasIdx + batchIndex * halfChannels * 2;
    let valueLeft = input[inputOffset] + bias[biasIdx];
    let valueRight = input[inputOffset + halfChannels] + bias[biasIdx + halfChannels];
    let geluRight = valueRight * 0.5 * (erf_vf32(valueRight / M_SQRT2) + 1);

    ${n.setByOffset("global_idx","valueLeft * geluRight")}
  }`}},Lp=e=>{Ro(e.inputs),e.compute(No(e.inputs))}}),Mo,Do,Ge,Gp,Hp,Fp,jp,Kp,Zp,Qp,Xp,Yp,Jp,Rm=P(()=>{ee(),ae(),ne(),Mo=(e,t,r,a,n,i,s,u,d,l,c,f)=>{let m,g;typeof u=="string"?m=g=(w,S)=>`${u}((${w}),(${S}))`:typeof u=="function"?m=g=u:(m=u.scalar,g=u.vector);let _=H("outputData",c,a.length,4),b=R("aData",d,t.length,4),x=R("bData",l,r.length,4),$;if(n)if(i){let w=O.size(t)===1,S=O.size(r)===1,k=t.length>0&&t[t.length-1]%4===0,T=r.length>0&&r[r.length-1]%4===0;w||S?$=_.setByOffset("global_idx",g(w?`${b.type.value}(${b.getByOffset("0")}.x)`:b.getByOffset("global_idx"),S?`${x.type.value}(${x.getByOffset("0")}.x)`:x.getByOffset("global_idx"))):$=`
            let outputIndices = ${_.offsetToIndices("global_idx * 4u")};
            let offsetA = ${b.broadcastedIndicesToOffset("outputIndices",_)};
            let offsetB = ${x.broadcastedIndicesToOffset("outputIndices",_)};
            ${_.setByOffset("global_idx",g(s||k?b.getByOffset("offsetA / 4u"):`${b.type.value}(${b.getByOffset("offsetA / 4u")}[offsetA % 4u])`,s||T?x.getByOffset("offsetB / 4u"):`${x.type.value}(${x.getByOffset("offsetB / 4u")}[offsetB % 4u])`))}
          `}else $=_.setByOffset("global_idx",g(b.getByOffset("global_idx"),x.getByOffset("global_idx")));else{if(!i)throw new Error("no necessary to use scalar implementation for element-wise binary op implementation.");let w=(S,k,T="")=>{let E=`aData[indexA${k}][componentA${k}]`,z=`bData[indexB${k}][componentB${k}]`;return`
            let outputIndices${k} = ${_.offsetToIndices(`global_idx * 4u + ${k}u`)};
            let offsetA${k} = ${b.broadcastedIndicesToOffset(`outputIndices${k}`,_)};
            let offsetB${k} = ${x.broadcastedIndicesToOffset(`outputIndices${k}`,_)};
            let indexA${k} = offsetA${k} / 4u;
            let indexB${k} = offsetB${k} / 4u;
            let componentA${k} = offsetA${k} % 4u;
            let componentB${k} = offsetB${k} % 4u;
            ${S}[${k}] = ${T}(${m(E,z)});
          `};c===9?$=`
            var data = vec4<u32>(0);
            ${w("data",0,"u32")}
            ${w("data",1,"u32")}
            ${w("data",2,"u32")}
            ${w("data",3,"u32")}
            outputData[global_idx] = dot(vec4<u32>(0x1, 0x100, 0x10000, 0x1000000), vec4<u32>(data));`:$=`
            ${w("outputData[global_idx]",0)}
            ${w("outputData[global_idx]",1)}
            ${w("outputData[global_idx]",2)}
            ${w("outputData[global_idx]",3)}
          `}return`
        ${e.registerUniform("vec_size","u32").declareVariables(b,x,_)}

        ${f??""}

        ${e.mainStart()}
        ${e.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.vec_size")}
        ${$}
      }`},Do=(e,t,r,a,n,i,s=r.dataType)=>{let u=r.dims.map(b=>Number(b)??1),d=a.dims.map(b=>Number(b)??1),l=!O.areEqual(u,d),c=u,f=O.size(u),m=!1,g=!1,_=[l];if(l){let b=Pt.calcShape(u,d,!1);if(!b)throw new Error("Can't perform binary op on the given tensors");c=b.slice(),f=O.size(c);let x=O.size(u)===1,$=O.size(d)===1,w=u.length>0&&u[u.length-1]%4===0,S=d.length>0&&d[d.length-1]%4===0;_.push(x),_.push($),_.push(w),_.push(S);let k=1;for(let T=1;T<c.length;T++){let E=u[u.length-T],z=d[d.length-T];if(E===z)k*=E;else break}k%4===0?(g=!0,m=!0):(x||$||w||S)&&(m=!0)}else m=!0;return _.push(m),{name:e,shaderCache:{hint:t+_.map(b=>b.toString()).join("_"),inputDependencies:["rank","rank"]},getShaderSource:b=>Mo(b,u,d,c,m,l,g,n,r.dataType,a.dataType,s,i),getRunData:()=>({outputs:[{dims:c,dataType:s}],dispatchGroup:{x:Math.ceil(f/64/4)},programUniforms:[{type:12,data:Math.ceil(O.size(c)/4)},...Q(u,d,c)]})}},Ge=(e,t,r,a,n,i)=>{e.compute(Do(t,n??"",e.inputs[0],e.inputs[1],r,a,i))},Gp=e=>{Ge(e,"Add",(t,r)=>`${t}+${r}`)},Hp=e=>{Ge(e,"Div",(t,r)=>`${t}/${r}`)},Fp=e=>{Ge(e,"Equal",{scalar:(t,r)=>`u32(${t}==${r})`,vector:(t,r)=>`vec4<u32>(${t}==${r})`},void 0,void 0,9)},jp=e=>{Ge(e,"Mul",(t,r)=>`${t}*${r}`)},Kp=e=>{let t=R("input",e.inputs[0].dataType,e.inputs[0].dims).type.value;Ge(e,"Pow",{scalar:(r,a)=>`pow_custom(${r},${a})`,vector:(r,a)=>`pow_vector_custom(${r},${a})`},`
    fn pow_custom(a : ${t}, b : ${t}) -> ${t} {
      if (b == ${t}(0.0)) {
        return ${t}(1.0);
      } else if (a < ${t}(0.0) && f32(b) != floor(f32(b))) {
        return ${t}(pow(f32(a), f32(b))); // NaN
      }
      return select(sign(a), ${t}(1.0), round(f32(abs(b) % ${t}(2.0))) != 1.0) * ${t}(${t==="i32"?"round":""}(pow(f32(abs(a)), f32(b))));
    }
    fn pow_vector_custom(a : vec4<${t}>, b : vec4<${t}>) -> vec4<${t}> {
      // TODO: implement vectorized pow
      return vec4<${t}>(pow_custom(a.x, b.x), pow_custom(a.y, b.y), pow_custom(a.z, b.z), pow_custom(a.w, b.w));
    }
      `)},Zp=e=>{Ge(e,"Sub",(t,r)=>`${t}-${r}`)},Qp=e=>{Ge(e,"Greater",{scalar:(t,r)=>`u32(${t}>${r})`,vector:(t,r)=>`vec4<u32>(${t}>${r})`},void 0,void 0,9)},Xp=e=>{Ge(e,"Less",{scalar:(t,r)=>`u32(${t}<${r})`,vector:(t,r)=>`vec4<u32>(${t}<${r})`},void 0,void 0,9)},Yp=e=>{Ge(e,"GreaterOrEqual",{scalar:(t,r)=>`u32(${t}>=${r})`,vector:(t,r)=>`vec4<u32>(${t}>=${r})`},void 0,void 0,9)},Jp=e=>{Ge(e,"LessOrEqual",{scalar:(t,r)=>`u32(${t}<=${r})`,vector:(t,r)=>`vec4<u32>(${t}<=${r})`},void 0,void 0,9)}}),Po,Uo,qo,Wo,ec,tc,Nm=P(()=>{ee(),ae(),ve(),ne(),Po=(e,t)=>{if(!e||e.length<1)throw new Error("too few inputs");let r=0,a=e[r],n=a.dataType,i=a.dims.length;e.forEach((s,u)=>{if(u!==r){if(s.dataType!==n)throw new Error("input tensors should be one type");if(s.dims.length!==i)throw new Error("input tensors should have the same shape");s.dims.forEach((d,l)=>{if(l!==t&&d!==a.dims[l])throw new Error("non concat dimensions must match")})}})},Uo=(e,t)=>`
  fn calculateInputIndex(index: u32) -> u32 {
    let sizeInConcatAxis = array<u32, ${e}u>(${t});
    for (var i: u32 = 0u; i < ${e}; i += 1u ) {
      if (index < sizeInConcatAxis[i]) {
        return i;
      }
    }
    return ${e}u;
  }`,qo=(e,t)=>{let r=e.length,a=[];for(let n=0;n<r;++n){let i=t.setByOffset("global_idx",e[n].getByIndices("indices"));r===1?a.push(i):n===0?a.push(`if (inputIndex == ${n}u) { ${i} }`):n===r-1?a.push(`else { ${i} }`):a.push(`else if (inputIndex == ${n}) { ${i} }`)}return a.join(`
`)},Wo=(e,t,r,a)=>{let n=O.size(r),i=new Array(e.length),s=new Array(e.length),u=0,d=[],l=[],c=[{type:12,data:n}];for(let b=0;b<e.length;++b)u+=e[b].dims[t],i[b]=u,l.push(e[b].dims.length),s[b]=R(`input${b}`,a,l[b]),d.push("rank"),c.push({type:12,data:i[b]});for(let b=0;b<e.length;++b)c.push(...Q(e[b].dims));c.push(...Q(r));let f=H("output",a,r.length),m=f.indicesGet("indices",t),g=Array.from(Array(i.length).keys()).map(b=>`uniforms.sizeInConcatAxis${b}`).join(","),_=b=>`

  ${(()=>{b.registerUniform("outputSize","u32");for(let x=0;x<e.length;x++)b.registerUniform(`sizeInConcatAxis${x}`,"u32");return b.declareVariables(...s,f)})()}

  ${Uo(i.length,g)}

  ${b.mainStart()}
    ${b.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.outputSize")}

    var indices = ${f.offsetToIndices("global_idx")};

    let inputIndex = calculateInputIndex(${m});
    if (inputIndex != 0u) {
      let sizeInConcatAxis = array<u32, ${i.length}u>(${g});
      ${m} -= sizeInConcatAxis[inputIndex - 1u];
    }

    ${qo(s,f)}
  }`;return{name:"Concat",shaderCache:{hint:`${t}`,inputDependencies:d},getRunData:()=>({outputs:[{dims:r,dataType:a}],dispatchGroup:{x:Math.ceil(n/64)},programUniforms:c}),getShaderSource:_}},ec=(e,t)=>{let r=e.inputs,a=r[0].dims,n=O.normalizeAxis(t.axis,a.length);Po(r,n);let i=a.slice();i[n]=r.reduce((u,d)=>u+(d.dims.length>n?d.dims[n]:0),0);let s=r.filter(u=>O.size(u.dims)>0);e.compute(Wo(s,n,i,r[0].dataType),{inputs:s})},tc=e=>pe({axis:e.axis})}),It,Et,zt,Ha,Ot=P(()=>{ee(),ae(),It=(e,t,r="f32")=>{switch(e.activation){case"Relu":return`value = max(value, ${t}(0.0));`;case"Sigmoid":return`value = (${t}(1.0) / (${t}(1.0) + exp(-value)));`;case"Clip":return`value = clamp(value, ${t}(${r}(uniforms.clip_min)), ${t}(${r}(uniforms.clip_max)));`;case"HardSigmoid":return`value = max(${t}(0.0), min(${t}(1.0), ${r}(uniforms.alpha) * value + ${r}(uniforms.beta)));`;case"LeakyRelu":return`value = select(${r}(uniforms.alpha) * value, value, value >= ${t}(0.0));`;case"Tanh":return`let e2x = exp(-2.0 * abs(value));
              value = sign(value) * (1.0 - e2x) / (1.0 + e2x);
        `;case"":return"";default:throw new Error(`Unsupported activation ${e.activation}`)}},Et=(e,t)=>{e.activation==="Clip"?t.push({type:1,data:e.clipMax},{type:1,data:e.clipMin}):e.activation==="HardSigmoid"?t.push({type:1,data:e.alpha},{type:1,data:e.beta}):e.activation==="LeakyRelu"&&t.push({type:1,data:e.alpha})},zt=(e,t)=>{e.activation==="Clip"?t.push({name:"clip_max",type:"f32"},{name:"clip_min",type:"f32"}):e.activation==="HardSigmoid"?t.push({name:"alpha",type:"f32"},{name:"beta",type:"f32"}):e.activation==="LeakyRelu"&&t.push({name:"alpha",type:"f32"})},Ha=e=>{let t=(e==null?void 0:e.activation)||"";if(t==="HardSigmoid"){let[r,a]=(e==null?void 0:e.activation_params)||[.2,.5];return{activation:t,alpha:r,beta:a}}else if(t==="Clip"){let[r,a]=(e==null?void 0:e.activation_params)||[Id,Ed];return{activation:t,clipMax:a,clipMin:r}}else if(t==="LeakyRelu"){let[r]=(e==null?void 0:e.activation_params)||[.01];return{activation:t,alpha:r}}return{activation:t}}}),Se,rc,Fa=P(()=>{Se=(e,t)=>{switch(e){case 1:return t;case 2:return`vec2<${t}>`;case 3:return`vec3<${t}>`;case 4:return`vec4<${t}>`;default:throw new Error(`${e}-component is not supported.`)}},rc=e=>`
      ${e?"value = value + getBiasByOutputCoords(coords);":""}
      `}),ic,Mm=P(()=>{ic=e=>`
fn getIndexFromCoords4D(coords : vec4<i32>, shape : vec4<i32>) -> i32 {
  return dot(coords, vec4<i32>(
      shape.y * shape.z * shape.w, shape.z * shape.w, shape.w, 1));
}
fn getOutputIndexFromCoords(coords : vec4<i32>) -> i32 {
  return dot(coords, vec4<i32>(
    i32(${e}.x), i32(${e}.y), i32(${e}.z), 1));
}
`}),sr,ja,Ka=P(()=>{ee(),ae(),ne(),Ot(),sr=(e,t,r,a,n)=>{let i=a-r;return`
      ${Array.from({length:r}).map((s,u)=>`
      if (${j(t.shape,u,t.rank)} != 1) {
        ${t.indicesSet(e,u,j(n,u+i,a))}
      } else {
        ${t.indicesSet(e,u,0)}
      }`).join("")}
`},ja=(e,t,r,a,n=!1,i)=>{let s=e[0].dims,u=e[1].dims,d=s[s.length-2],l=u[u.length-1],c=s[s.length-1],f=$e(l),m=$e(c),g=$e(d),_=O.size(r)/f/g,b=e.length>2,x=a?a.slice(0,-2):r.slice(0,-2),$=[O.size(x),d,l],w=[{type:12,data:_},{type:12,data:d},{type:12,data:l},{type:12,data:c}];Et(t,w),w.push(...Q(x,s,u)),b&&w.push(...Q(e[2].dims)),w.push(...Q($));let S=k=>{let T=Wa("batch_dims",e[0].dataType,x.length),E=R("a",e[0].dataType,s.length,m),z=R("b",e[1].dataType,u.length,f),C=H("output",e[0].dataType,$.length,f),A=ke(C.type.tensor),q=It(t,C.type.value,A),X=[E,z],G="";if(b){let re=n?f:1;X.push(R("bias",e[2].dataType,e[2].dims.length,re)),G=`${n?`value += bias[col / ${re}];`:`value += ${C.type.value}(bias[row + i]);`}`}let Z=[{name:"output_size",type:"u32"},{name:"M",type:"u32"},{name:"N",type:"u32"},{name:"K",type:"u32"}];zt(t,Z);let oe=()=>{let re=`var a_data: ${E.type.value};`;for(let L=0;L<m;L++)re+=`
              let b_data${L} = b[(b_offset + (k + ${L}) * uniforms.N + col) / ${f}];`;for(let L=0;L<g;L++){re+=`a_data = a[(a_offset + (row + ${L}) * uniforms.K + k) / ${m}];`;for(let ie=0;ie<m;ie++)re+=`
            values[${L}] = fma(${z.type.value}(a_data${m===1?"":`[${ie}]`}), b_data${ie}, values[${L}]);
`}return re};return`
  ${k.registerUniforms(Z).registerInternalVariables(T).declareVariables(...X,C)}
  ${k.mainStart()}
    ${k.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}
    let col = (global_idx % (uniforms.N / ${f})) * ${f};
    var index1 = global_idx / (uniforms.N / ${f});
    let stride1 = uniforms.M / ${g};
    let row = (index1 % stride1) * ${g};
    let batch = index1 / stride1;

    ${r.length===2?"":`let batch_indices = ${T.offsetToIndices("batch")};`}

    var a_indices: ${E.type.indices};
    ${sr("a_indices",E,E.rank-2,T.rank,"batch_indices")}
    ${E.indicesSet("a_indices",E.rank-2,0)}
    ${E.indicesSet("a_indices",E.rank-1,0)}
    let a_offset = ${E.indicesToOffset("a_indices")};

    var b_indices: ${z.type.indices};
    ${sr("b_indices",z,z.rank-2,T.rank,"batch_indices")}
    ${z.indicesSet("b_indices",z.rank-2,0)}
    ${z.indicesSet("b_indices",z.rank-1,0)}
    let b_offset = ${z.indicesToOffset("b_indices")};
    var values: array<${C.type.value}, ${g}>;
    for (var k: u32 = 0u; k < uniforms.K; k = k + ${m}) {
      ${oe()}
    }
    for (var i = 0u; i < ${g}u; i++) {
      var value = values[i];
      ${G}
      ${q}
      let cur_indices = ${C.type.indices}(batch, row + i, col);
      let offset = ${C.indicesToOffset("cur_indices")};
      ${C.setByOffset(`offset / ${f}`,"value")};
    }
  }
  `};return{name:"MatMulNaive",shaderCache:{hint:`${t.activation};${f};${m};${g};${n}`,inputDependencies:b?["rank","rank","rank"]:["rank","rank"]},getRunData:()=>({outputs:[{dims:i?i(r):r,dataType:e[0].dataType}],dispatchGroup:{x:Math.ceil(_/64)},programUniforms:w}),getShaderSource:S}}}),Vo,Lo,$a,Ni,Go,va,Ho,qr,Za=P(()=>{ee(),ae(),ne(),Ot(),Ka(),Fa(),Vo=(e,t)=>e?`
        mm_Asub[inputRow][inputCol] = mm_readA(batch,
          kStart + inputRow,
          globalRowStart / innerElementSize + inputCol${t?", batchIndices":""});
        `:`
        mm_Asub[inputRow][inputCol] = mm_readA(batch,
          globalRow + innerRow,
          kStart / innerElementSize + inputCol${t?", batchIndices":""});
        `,Lo=(e,t)=>e?`
        let ACached0 = mm_Asub[k * innerElementSize][localRow];
        let ACached1 = mm_Asub[k * innerElementSize + 1][localRow];
        let ACached2 = mm_Asub[k * innerElementSize + 2][localRow];
        ${t===3?"":"let ACached3 = mm_Asub[k * innerElementSize + 3][localRow];"}
        for (var i = 0; i < rowPerThread; i = i + 1) {
          acc[i] = BCached0 * ACached0[i] + acc[i];
          acc[i] = BCached1 * ACached1[i] + acc[i];
          acc[i] = BCached2 * ACached2[i] + acc[i];
          ${t===3?"":"acc[i] = BCached3 * ACached3[i] + acc[i];"}
        }`:`
        for (var i = 0; i < rowPerThread; i = i + 1) {
          let ACached = mm_Asub[tileRow + i][k];
          acc[i] = BCached0 * ACached.x + acc[i];
          acc[i] = BCached1 * ACached.y + acc[i];
          acc[i] = BCached2 * ACached.z + acc[i];
          ${t===3?"":"acc[i] = BCached3 * ACached.w + acc[i];"}
        }`,$a=(e,t,r="f32",a,n=!1,i=32,s=!1,u=32)=>{let d=t[1]*e[1],l=t[0]*e[0],c=n?d:i,f=n?i:d,m=c/t[0],g=i/t[1];if(!((n&&m===4&&e[1]===4||!n&&(m===3||m===4))&&c%t[0]===0&&i%t[1]===0&&e[0]===4))throw new Error(`If transposeA ${n} is true, innerElementSize ${m} and workPerThread[1] ${e[1]} must be 4.
      Otherwise, innerElementSize ${m} must be 3 or 4.
  tileAWidth ${c} must be divisible by workgroupSize[0]${t[0]}. tileInner ${i} must be divisible by workgroupSize[1] ${t[1]}. colPerThread ${e[0]} must be 4.`);return`
var<workgroup> mm_Asub: array<array<vec${m}<${r}>, ${c/m}>, ${f}>;
var<workgroup> mm_Bsub: array<array<vec4<${r}>, ${l/e[0]}>, ${i}>;

const rowPerThread = ${e[1]};
const colPerThread = ${e[0]};
const innerElementSize = ${m};
const tileInner = ${i};

@compute @workgroup_size(${t[0]}, ${t[1]}, ${t[2]})
fn main(@builtin(local_invocation_id) localId : vec3<u32>,
        @builtin(global_invocation_id) globalId : vec3<u32>,
        @builtin(workgroup_id) workgroupId : vec3<u32>) {
  let localRow = i32(localId.y);
  let tileRow = localRow * rowPerThread;
  let tileCol = i32(localId.x);

  let globalRow =i32(globalId.y) * rowPerThread;
  let globalCol = i32(globalId.x);
  let batch = ${s?"0":"i32(globalId.z)"};
  ${a?`let batchIndices = ${a.offsetToIndices("u32(batch)")};`:""}
  let globalRowStart = i32(workgroupId.y) * ${d};

  let num_tiles = ${s?`${Math.ceil(u/i)}`:"(uniforms.dim_inner - 1) / tileInner + 1"};
  var kStart = ${s?`i32(globalId.z) * ${u}`:"0"};

  var acc: array<vec4<${r}>, rowPerThread>;

  // Loop over shared dimension.
  let tileRowB = localRow * ${g};
  for (var t = 0; t < num_tiles; t = t + 1) {
      // Load one tile of A into local memory.
      for (var innerRow = 0; innerRow < rowPerThread; innerRow = innerRow + 1) {
          let inputRow = tileRow + innerRow;
          let inputCol = tileCol;
          ${Vo(n,a)}
      }

      // Load one tile of B into local memory.
      for (var innerRow = 0; innerRow < ${g}; innerRow = innerRow + 1) {
          let inputRow = tileRowB + innerRow;
          let inputCol = tileCol;
          mm_Bsub[inputRow][inputCol] = mm_readB(batch, kStart + inputRow, globalCol${a?", batchIndices":""});
      }
      kStart = kStart + tileInner;
      workgroupBarrier();

      // Compute acc values for a single thread.
      for (var k = 0; k < tileInner / innerElementSize; k = k + 1) {
          let BCached0 = mm_Bsub[k * innerElementSize][tileCol];
          let BCached1 = mm_Bsub[k * innerElementSize + 1][tileCol];
          let BCached2 = mm_Bsub[k * innerElementSize + 2][tileCol];
          ${m===3?"":"let BCached3 = mm_Bsub[k * innerElementSize + 3][tileCol];"}

          ${Lo(n,m)}
      }

      workgroupBarrier();
  }

  for (var innerRow = 0; innerRow < rowPerThread; innerRow = innerRow + 1) {
      mm_write(batch, globalRow + innerRow, globalCol, acc[innerRow]);
  }
}`},Ni=(e,t)=>e?`
            mm_Asub[inputRow][inputCol] = mm_readA(batch,
              kStart + inputRow,
              globalRowStart + inputCol${t?", batchIndices":""});
            `:`
            mm_Asub[inputRow][inputCol] = mm_readA(batch,
              globalRowStart + inputRow,
              kStart + inputCol${t?", batchIndices":""});
            `,Go=e=>e?"let ACached = mm_Asub[k][tileRow + innerRow];":"let ACached = mm_Asub[tileRow + innerRow][k];",va=(e,t,r="f32",a,n=!1,i=32,s=!1,u=32,d=!1)=>{let l=e[1]*t[1],c=e[0]*t[0],f=n?l:i,m=n?i:l;if(!(m%t[1]===0&&f%t[0]===0&&i%t[1]===0))throw new Error(`tileAHight ${m} must be divisible by workgroupSize[1]${t[1]}, tileAWidth ${f} must be divisible by workgroupSize[0]${t[0]}, tileInner ${i} must be divisible by workgroupSize[1]${t[1]}`);let g=m/t[1],_=f/t[0],b=i/t[1],x=d?`
    let localRow = i32(localId.y);
    let localCol = i32(localId.x);
    let globalRowStart = i32(workgroupId.y) * ${l};
    let globalColStart = i32(workgroupId.x) * ${c};

    // Loop over shared dimension.
    for (var t = 0; t < num_tiles; t = t + 1) {
      // Load one tile of A into local memory.
      for (var inputRow = localRow; inputRow < ${m}; inputRow = inputRow + ${t[1]}) {
        for (var inputCol = localCol; inputCol < ${f}; inputCol = inputCol + ${t[0]}) {
          ${Ni(n,a)}
        }
      }
      // Load one tile of B into local memory.
      for (var inputRow = localRow; inputRow < ${i}; inputRow = inputRow + ${t[1]}) {
            for (var inputCol = localCol; inputCol < ${c}; inputCol = inputCol + ${t[0]}) {
          mm_Bsub[inputRow][inputCol] = mm_readB(batch,
            kStart + inputRow,
            globalColStart + inputCol${a?", batchIndices":""});
        }
      }
      kStart = kStart + tileInner;
      workgroupBarrier();

      // Compute acc values for a single thread.
      var BCached : array<${r}, colPerThread>;
      for (var k = 0; k < tileInner; k = k + 1) {
        for (var inner = 0; inner < colPerThread; inner = inner + 1) {
          BCached[inner] = mm_Bsub[k][localCol + inner * ${t[0]}];
        }
        for (var innerRow = 0; innerRow < rowPerThread; innerRow = innerRow + 1) {
          let ACached = ${n?`mm_Asub[k][localRow + innerRow * ${t[1]}];`:`mm_Asub[localRow + innerRow * ${t[1]}][k];`}
          for (var innerCol = 0; innerCol < colPerThread; innerCol = innerCol + 1) {
            acc[innerRow][innerCol] = acc[innerRow][innerCol] +
                ACached * BCached[innerCol];
          }
        }
      }
      workgroupBarrier();
    }
    for (var innerRow = 0; innerRow < rowPerThread; innerRow = innerRow + 1) {
      let gRow = globalRowStart + localRow + innerRow * ${t[1]};
      for (var innerCol = 0; innerCol < colPerThread; innerCol = innerCol + 1) {
        let gCol = globalColStart + localCol + innerCol * ${t[0]};
        mm_write(batch, gRow, gCol, acc[innerRow][innerCol]);
      }
    }
    `:`
let tileRow = i32(localId.y) * rowPerThread;
let tileCol = i32(localId.x) * colPerThread;

let globalRow = i32(globalId.y) * rowPerThread;
let globalCol = i32(globalId.x) * colPerThread;
let globalRowStart = i32(workgroupId.y) * ${l};

let tileRowA = i32(localId.y) * ${g};
let tileColA = i32(localId.x) * ${_};
let tileRowB = i32(localId.y) * ${b};
// Loop over shared dimension.
for (var t = 0; t < num_tiles; t = t + 1) {
  // Load one tile of A into local memory.
  for (var innerRow = 0; innerRow < ${g}; innerRow = innerRow + 1) {
    for (var innerCol = 0; innerCol < ${_}; innerCol = innerCol + 1) {
      let inputRow = tileRowA + innerRow;
      let inputCol = tileColA + innerCol;
      ${Ni(n,a)}
    }
  }

  // Load one tile of B into local memory.
  for (var innerRow = 0; innerRow < ${b}; innerRow = innerRow + 1) {
    for (var innerCol = 0; innerCol < colPerThread; innerCol = innerCol + 1) {
      let inputRow = tileRowB + innerRow;
      let inputCol = tileCol + innerCol;
      mm_Bsub[inputRow][inputCol] = mm_readB(batch,
        kStart + inputRow,
        globalCol + innerCol${a?", batchIndices":""});
    }
  }
  kStart = kStart + tileInner;
  workgroupBarrier();

  // Compute acc values for a single thread.
  var BCached : array<${r}, colPerThread>;
  for (var k = 0; k < tileInner; k = k + 1) {
    for (var inner = 0; inner < colPerThread; inner = inner + 1) {
      BCached[inner] = mm_Bsub[k][tileCol + inner];
    }

    for (var innerRow = 0; innerRow < rowPerThread; innerRow = innerRow + 1) {
      ${Go(n)}
      for (var innerCol = 0; innerCol < colPerThread; innerCol = innerCol + 1) {
        acc[innerRow][innerCol] = acc[innerRow][innerCol] + ACached * BCached[innerCol];
      }
    }
  }

  workgroupBarrier();
}

for (var innerRow = 0; innerRow < rowPerThread; innerRow = innerRow + 1) {
  for (var innerCol = 0; innerCol < colPerThread; innerCol = innerCol + 1) {
    mm_write(batch, globalRow + innerRow, globalCol + innerCol,
        acc[innerRow][innerCol]);
  }
}
`;return`
  var<workgroup> mm_Asub : array<array<${r}, ${f}>, ${m}>;
  var<workgroup> mm_Bsub : array<array<${r}, ${c}>, ${i}>;
  const rowPerThread = ${e[1]};
  const colPerThread = ${e[0]};
  const tileInner = ${i};

@compute @workgroup_size(${t[0]}, ${t[1]}, ${t[2]})
fn main(@builtin(local_invocation_id) localId : vec3<u32>,
        @builtin(global_invocation_id) globalId : vec3<u32>,
        @builtin(workgroup_id) workgroupId : vec3<u32>) {
    let batch = ${s?"0":"i32(globalId.z)"};
    ${a?`let batchIndices = ${a.offsetToIndices("u32(batch)")};`:""}
    let num_tiles = ${s?`${Math.ceil(u/i)}`:"(uniforms.dim_inner - 1) / tileInner + 1"};
    var kStart = ${s?`i32(globalId.z) * ${u}`:"0"};

    var acc : array<array<${r}, colPerThread>, rowPerThread>;
    ${x}
  }
`},Ho=(e,t,r,a,n=!1)=>{let[i,s,u,d]=a,l=ke(a[0].type.tensor);return`
    fn mm_readA(batch: i32, row: i32, colIn: i32, batchIndices: ${i.type.indices}) -> ${Se(e,l)} {
      var value = ${Se(e,l)}(0.0);
      let col = colIn * ${e};
      if(row < uniforms.dim_a_outer && col < uniforms.dim_inner)
      {
        var aIndices: ${s.type.indices};
        ${sr("aIndices",s,s.rank-2,i.rank,"batchIndices")}
        ${s.indicesSet("aIndices",s.rank-2,"u32(row)")}
        ${s.indicesSet("aIndices",s.rank-1,"u32(colIn)")}
        value = ${s.getByIndices("aIndices")};
      }
      return value;
    }

    fn mm_readB(batch: i32, row: i32, colIn: i32, batchIndices: ${i.type.indices}) -> ${Se(e,l)} {
      var value = ${Se(e,l)}(0.0);
      let col = colIn * ${e};
      if(row < uniforms.dim_inner && col < uniforms.dim_b_outer)
      {
        var bIndices: ${u.type.indices};
        ${sr("bIndices",u,u.rank-2,i.rank,"batchIndices")}
        ${u.indicesSet("bIndices",u.rank-2,"u32(row)")}
        ${u.indicesSet("bIndices",u.rank-1,"u32(colIn)")}
        value = ${u.getByIndices("bIndices")};
      }
      return value;
    }

    fn mm_write(batch: i32, row: i32, colIn: i32, valueIn: ${Se(e,l)}) {
      let col = colIn * ${e};
      if (row < uniforms.dim_a_outer && col < uniforms.dim_b_outer) {
        var value = valueIn;
        let coords = vec3<i32>(batch, row, colIn);
        ${t?`value = value + ${n?"bias[colIn]":`${Se(e,l)}(bias[row])`};`:""}
        ${r}
        ${d.setByIndices("vec3<u32>(coords)","value")}
      }
    }
    `},qr=(e,t,r,a,n=!1,i)=>{let s=e[0].dims,u=e[1].dims,d=s.slice(0,-2),l=u.slice(0,-2),c=a?a.slice(0,-2):r.slice(0,-2),f=O.size(c),m=s[s.length-2],g=s[s.length-1],_=u[u.length-1],b=g%4===0&&_%4===0,x=m<=8?[4,1,1]:[4,4,1],$=[8,8,1],w=[Math.ceil(_/$[0]/x[0]),Math.ceil(m/$[1]/x[1]),Math.ceil(f/$[2]/x[2])],S=b?4:1,k=[...d,m,g/S],T=k.length,E=[...l,g,_/S],z=E.length,C=[f,m,_/S],A=[{type:6,data:m},{type:6,data:_},{type:6,data:g}];Et(t,A),A.push(...Q(c,k,E));let q=["rank","rank"],X=e.length>2;X&&(A.push(...Q(e[2].dims)),q.push("rank")),A.push(...Q(C));let G=Z=>{let oe=c.length,re=Wa("batchDims",e[0].dataType,oe,1),L=ke(e[0].dataType),ie=R("a",e[0].dataType,T,S),F=R("b",e[1].dataType,z,S),Y=H("result",e[0].dataType,C.length,S),ye=[ie,F];if(X){let Te=n?S:1;ye.push(R("bias",e[2].dataType,e[2].dims.length,Te))}let N=[{name:"dim_a_outer",type:"i32"},{name:"dim_b_outer",type:"i32"},{name:"dim_inner",type:"i32"}];zt(t,N);let U=ke(Y.type.tensor),V=It(t,Y.type.value,U),te=Ho(S,X,V,[re,ie,F,Y],n);return`
  ${Z.registerUniforms(N).registerInternalVariables(re).declareVariables(...ye,Y)}
  ${te}
  ${b?$a(x,$,L,re):va(x,$,L,re)}
                   `};return{name:"MatMul",shaderCache:{hint:`${x};${t.activation};${b};${n}`,inputDependencies:q},getRunData:()=>({outputs:[{dims:i?i(r):r,dataType:e[0].dataType}],dispatchGroup:{x:w[0],y:w[1],z:w[2]},programUniforms:A}),getShaderSource:G}}}),Fo,ac,Dm=P(()=>{ee(),nt(),ne(),Ot(),Fa(),Mm(),Za(),Fo=(e,t,r,a,n=!1,i,s=4,u=4,d=4,l="f32")=>{let c=A=>{switch(A){case 1:return"resData = x[xIndex];";case 3:return`resData = vec3<${l}>(x[xIndex], x[xIndex + 1], x[xIndex + 2]);`;case 4:return"resData = x[xIndex / 4];";default:throw new Error(`innerElementSize ${A} is not supported.`)}},f=A=>{switch(A){case 1:return"return w[row * i32(uniforms.w_shape[3]) + colIn];";case 4:return"return w[row * i32(uniforms.w_shape[3]) / 4 + colIn];";default:throw new Error(`innerElementSize ${A} is not supported.`)}},m=e?`
    let coord = vec4<i32>(batch, xRow, xCol, xCh);
    `:`
    let coord = vec4<i32>(batch, xCh, xRow, xCol);
    `,g=e?`
    let coords = vec4<i32>(
      batch,
      row / outWidth,
      row % outWidth,
      col);
    `:`
    let coords = vec4<i32>(
      batch,
      row,
      col / outWidth,
      col % outWidth);
    `,_=e?"i32(uniforms.x_shape[1])":"i32(uniforms.x_shape[2])",b=e?"i32(uniforms.x_shape[2])":"i32(uniforms.x_shape[3])",x=e?"row":"col",$=e?"col":"row",w=`
    let inChannels = i32(uniforms.w_shape[2]);
    let outWidth = ${e?"i32(uniforms.result_shape[2])":"i32(uniforms.result_shape[3])"};
    let outRow = ${x} / outWidth;
    let outCol = ${x} % outWidth;

    let WRow = ${$} / (i32(uniforms.w_shape[1]) * inChannels);
    let WCol = ${$} / inChannels % i32(uniforms.w_shape[1]);
    let xRow = outRow * uniforms.stride[0] + uniforms.dilation[0] * WRow - uniforms.pad[0];
    let xCol = outCol * uniforms.stride[1] + uniforms.dilation[1] * WCol - uniforms.pad[1];
    let xCh = ${$} % inChannels;
    var resData = ${Se(s,l)}(0.0);
    // The bounds checking is always needed since we use it to pad zero for
    // the 'same' padding type.
    if (xRow >= 0 && xRow < ${_} && xCol >= 0 && xCol < ${b}) {
      ${m}
      let xIndex = getIndexFromCoords4D(coord, vec4<i32>(uniforms.x_shape));
      ${c(s)}
    }
    return resData;`,S=e?t&&a?`
    let col = colIn * ${s};
    ${w}`:`
    let col = colIn * ${s};
    if (row < uniforms.dim_a_outer && col < uniforms.dim_inner) {
      ${w}
    }
    return ${Se(s,l)}(0.0);`:a&&r?`
    let col = colIn * ${s};
    ${w}`:`
    let col = colIn * ${s};
    if (row < uniforms.dim_inner && col < uniforms.dim_b_outer) {
      ${w}
    }
    return ${Se(s,l)}(0.0);`,k=e?a&&r?f(u):`
    let col = colIn * ${u};
    if (row < uniforms.dim_inner && col < uniforms.dim_b_outer) {
      ${f(u)}
    }
    return ${Se(u,l)}(0.0);`:`
    let col = colIn * ${u};
    if (row < uniforms.dim_inner && col < uniforms.dim_a_outer) {
      ${f(u)}
    }
    return ${Se(u,l)}(0.0);`,T=Se(d,l),E=Se(e?s:u,l),z=Se(e?u:s,l),C=It(i,T,l);return`
    fn mm_readA(batch: i32, row : i32, colIn : i32) -> ${E} {
      ${e?S:k}
    }

    fn mm_readB(batch: i32, row : i32, colIn : i32) -> ${z} {
      ${e?k:S}
    }

    fn mm_write(batch: i32, row : i32, colIn : i32, valueIn : ${T}) {
      let col = colIn * ${d};
      if (row < uniforms.dim_a_outer && col < uniforms.dim_b_outer)
      {
      var value = valueIn;
      let outWidth = ${e?"i32(uniforms.result_shape[2])":"i32(uniforms.result_shape[3])"};
      ${g}
      ${rc(n)}
      ${C}
      setOutputAtCoords(coords[0], coords[1], coords[2], coords[3], value);
      }
    }`},ac=(e,t,r,a,n,i,s,u,d)=>{let l=t.format==="NHWC",c=l?e[0].dims[3]:e[0].dims[1],f=r[0],m=l?r[2]:r[3],g=l?r[1]:r[2],_=l?r[3]:r[1],b=l&&(c%4===0||c%3===0)&&_%4===0,x=l?_:m*g,$=l?m*g:_,w=[8,8,1],S=a<=8?[4,1,1]:[4,4,1],k=[Math.ceil(x/w[0]/S[0]),Math.ceil($/w[1]/S[1]),Math.ceil(f/w[2]/S[2])];ue("verbose",()=>`[conv2d_mm_webgpu] dispatch = ${k}`);let T=b?l&&c%4!==0?3:4:1,E=w[1]*S[1],z=w[0]*S[0],C=Math.max(w[0]*T,w[1]),A=a%E===0,q=n%z===0,X=i%C===0,G=b?[T,4,4]:[1,1,1],Z=[{type:6,data:a},{type:6,data:n},{type:6,data:i},{type:6,data:[t.pads[0],t.pads[1]]},{type:6,data:t.strides},{type:6,data:t.dilations}];Et(t,Z),Z.push(...Q(e[0].dims,e[1].dims));let oe=["rank","rank"];s&&(Z.push(...Q(e[2].dims)),oe.push("rank")),Z.push(...Q(r));let re=L=>{let ie=[{name:"dim_a_outer",type:"i32"},{name:"dim_b_outer",type:"i32"},{name:"dim_inner",type:"i32"},{name:"pad",type:"i32",length:2},{name:"stride",type:"i32",length:2},{name:"dilation",type:"i32",length:2}];zt(t,ie);let F=b?4:1,Y=ke(e[0].dataType),ye=`
      fn setOutputAtIndex(flatIndex : i32, value : ${b?`vec4<${Y}>`:Y}) {
        result[flatIndex] = ${b?`vec4<${Y}>`:Y}(value);
      }
      fn setOutputAtCoords(d0 : i32, d1 : i32, d2 : i32, d3 : i32, value : ${b?`vec4<${Y}>`:Y}) {
        let flatIndex = getOutputIndexFromCoords(vec4<i32>(d0, d1, d2, d3));
        setOutputAtIndex(flatIndex ${b?"/ 4":""}, value);
      }`,N=R("x",e[0].dataType,e[0].dims.length,T===3?1:T),U=R("w",e[1].dataType,e[1].dims.length,F),V=[N,U],te=H("result",e[0].dataType,r.length,F);if(s){let Te=R("bias",e[2].dataType,e[2].dims.length,F);V.push(Te),ye+=`
        fn getBiasByOutputCoords(coords : vec4<i32>) -> ${b?`vec4<${Y}>`:Y} {
          return bias[coords.${l?"w":"y"}${b?"/ 4":""}];
        }`}return`
        ${ic("uniforms.result_strides")}
        //struct Uniforms { xShape : vec4<i32>, wShape : vec4<i32>, outShape : vec4<i32>,
        //  outShapeStrides: vec3<i32>, filterDims : vec2<i32>, pad : vec2<i32>, stride : vec2<i32>,
        //  dilation : vec2<i32>, dimAOuter : i32, dimBOuter : i32, dimInner : i32 };
        ${L.registerUniforms(ie).declareVariables(...V,te)}
        ${ye}
        ${Fo(l,A,q,X,s,t,G[0],G[1],G[2],Y)}
        ${b?$a(S,w,Y,void 0,!l,C):va(S,w,Y,void 0,!l,C,!1,void 0,u)}`};return{name:"Conv2DMatMul",shaderCache:{hint:`${t.cacheKey};${T};${b};${A};${q};${X};${E};${z};${C}`,inputDependencies:oe},getRunData:()=>({outputs:[{dims:d?d(r):r,dataType:e[0].dataType}],dispatchGroup:{x:k[0],y:k[1],z:k[2]},programUniforms:Z}),getShaderSource:re}}}),jo,Mi,Zt,Ko,Di,Zo,nc,sc,Pm=P(()=>{ee(),nt(),ae(),ne(),Ot(),Fa(),jo=e=>{let t=1;for(let r=0;r<e.length;r++)t*=e[r];return t},Mi=e=>typeof e=="number"?[e,e,e]:e,Zt=(e,t)=>t<=1?e:e+(e-1)*(t-1),Ko=(e,t,r,a=1)=>{let n=Zt(t,a);return Math.floor((e[0]*(r-1)-r+n)/2)},Di=(e,t,r,a,n)=>{n==null&&(n=Ko(e,t[0],a[0]));let i=[0,0,0,r];for(let s=0;s<3;s++)e[s]+2*n>=t[s]&&(i[s]=Math.trunc((e[s]-t[s]+2*n)/a[s]+1));return i},Zo=(e,t,r,a,n,i,s,u,d,l)=>{let c,f,m,g;if(e==="VALID"&&(e=0),typeof e=="number"){c={top:e,bottom:e,left:e,right:e,front:e,back:e};let _=Di([t,r,a,1],[u,d,l],1,[n,i,s],e);f=_[0],m=_[1],g=_[2]}else if(Array.isArray(e)){if(!e.every((b,x,$)=>b===$[0]))throw Error(`Unsupported padding parameter: ${e}`);c={top:e[0],bottom:e[1],left:e[2],right:e[3],front:e[4],back:e[5]};let _=Di([t,r,a,1],[u,d,l],1,[n,i,s],e[0]);f=_[0],m=_[1],g=_[2]}else if(e==="SAME_UPPER"){f=Math.ceil(t/n),m=Math.ceil(r/i),g=Math.ceil(a/s);let _=(f-1)*n+u-t,b=(m-1)*i+d-r,x=(g-1)*s+l-a,$=Math.floor(_/2),w=_-$,S=Math.floor(b/2),k=b-S,T=Math.floor(x/2),E=x-T;c={top:S,bottom:k,left:T,right:E,front:$,back:w}}else throw Error(`Unknown padding parameter: ${e}`);return{padInfo:c,outDepth:f,outHeight:m,outWidth:g}},nc=(e,t,r,a,n,i=!1,s="channelsLast")=>{let u,d,l,c,f;if(s==="channelsLast")[u,d,l,c,f]=e;else if(s==="channelsFirst")[u,f,d,l,c]=e;else throw new Error(`Unknown dataFormat ${s}`);let[m,,g,_,b]=t,[x,$,w]=Mi(r),[S,k,T]=Mi(a),E=Zt(g,S),z=Zt(_,k),C=Zt(b,T),{padInfo:A,outDepth:q,outHeight:X,outWidth:G}=Zo(n,d,l,c,x,$,w,E,z,C),Z=i?m*f:m,oe=[0,0,0,0,0];return s==="channelsFirst"?oe=[u,Z,q,X,G]:s==="channelsLast"&&(oe=[u,q,X,G,Z]),{batchSize:u,dataFormat:s,inDepth:d,inHeight:l,inWidth:c,inChannels:f,outDepth:q,outHeight:X,outWidth:G,outChannels:Z,padInfo:A,strideDepth:x,strideHeight:$,strideWidth:w,filterDepth:g,filterHeight:_,filterWidth:b,effectiveFilterDepth:E,effectiveFilterHeight:z,effectiveFilterWidth:C,dilationDepth:S,dilationHeight:k,dilationWidth:T,inShape:e,outShape:oe,filterShape:t}},sc=(e,t,r,a,n,i)=>{let s=i==="channelsLast";s?e[0].dims[3]:e[0].dims[1];let u=[64,1,1],d={x:r.map((x,$)=>$)},l=[Math.ceil(jo(d.x.map(x=>r[x]))/u[0]),1,1];ue("verbose",()=>`[conv3d_naive_webgpu] dispatch = ${l}`);let c=1,f=O.size(r),m=[{type:12,data:f},{type:12,data:a},{type:12,data:n},{type:12,data:t.strides},{type:12,data:t.dilations}];Et(t,m),m.push(...Q(e[0].dims,e[1].dims));let g=["rank","rank"],_=e.length===3;_&&(m.push(...Q(e[2].dims)),g.push("rank")),m.push(...Q(r));let b=x=>{let $=[{name:"output_size",type:"u32"},{name:"filter_dims",type:"u32",length:a.length},{name:"pads",type:"u32",length:n.length},{name:"strides",type:"u32",length:t.strides.length},{name:"dilations",type:"u32",length:t.dilations.length}];zt(t,$);let w=1,S=ke(e[0].dataType),k=R("x",e[0].dataType,e[0].dims.length,c),T=R("W",e[1].dataType,e[1].dims.length,w),E=[k,T],z=H("result",e[0].dataType,r.length,w),C="";if(_){let X=R("bias",e[2].dataType,e[2].dims.length,w);E.push(X),C+=`
        fn getBiasByOutputCoords(coords : array<u32, 5>) -> ${S} {
          return bias[${s?j("coords",4,5):j("coords",1,5)}];
        }`}let A=Se(c,S),q=It(t,A,S);return`
            ${C}
            fn getX(d0 : u32, d1 : u32, d2 : u32, d3 : u32, d4 : u32) -> f32 {
              let aIndices = array<u32, 5>(d0, d1, d2, d3, d4);
              return ${k.getByIndices("aIndices")};
            }
            fn getW(d0 : u32, d1 : u32, d2 : u32, d3 : u32, d4 : u32) -> f32 {
              let aIndices = array<u32, 5>(d0, d1, d2, d3, d4);
              return ${T.getByIndices("aIndices")};
            }
          ${x.registerUniforms($).declareVariables(...E,z)}
          ${x.mainStart()}
          ${x.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}
              let coords = ${z.offsetToIndices("global_idx")};
              let batch = ${j("coords",0,k.rank)};
              let d2 = ${s?j("coords",k.rank-1,k.rank):j("coords",1,k.rank)};
              let xFRCCorner = vec3<u32>(${s?j("coords",1,k.rank):j("coords",2,k.rank)},
              ${s?j("coords",2,k.rank):j("coords",3,k.rank)},
              ${s?j("coords",3,k.rank):j("coords",4,k.rank)}) * uniforms.strides - uniforms.pads;
              let xFCorner = xFRCCorner.x;
              let xRCorner = xFRCCorner.y;
              let xCCorner = xFRCCorner.z;
              let xShapeY = ${s?j("uniforms.x_shape",1,k.rank):j("uniforms.x_shape",2,k.rank)};
              let xShapeZ = ${s?j("uniforms.x_shape",2,k.rank):j("uniforms.x_shape",3,k.rank)};
              let xShapeW = ${s?j("uniforms.x_shape",3,k.rank):j("uniforms.x_shape",4,k.rank)};
              let xShapeU = ${s?j("uniforms.x_shape",4,k.rank):j("uniforms.x_shape",1,k.rank)};
              let inputDepthNearestVec4 = (xShapeU / 4) * 4;
              let inputDepthVec4Remainder = xShapeU % 4;

              var value = 0.0;
              for (var wF = 0u; wF < uniforms.filter_dims[0]; wF++) {
                let xF = xFCorner + wF * uniforms.dilations[0];
                if (xF < 0 || xF >= xShapeY) {
                  continue;
                }

                for (var wR = 0u; wR < uniforms.filter_dims[1]; wR++) {
                  let xR = xRCorner + wR * uniforms.dilations[1];
                  if (xR < 0 || xR >= xShapeZ) {
                    continue;
                  }

                  for (var wC = 0u; wC < uniforms.filter_dims[2]; wC++) {
                    let xC = xCCorner + wC * uniforms.dilations[2];
                    if (xC < 0 || xC >= xShapeW) {
                      continue;
                    }

                    for (var d1 = 0u; d1 < inputDepthNearestVec4; d1 += 4) {
                      ${s?`let xValues = vec4<f32>(
                               getX(batch, xF, xR, xC, d1),
                               getX(batch, xF, xR, xC, d1 + 1),
                               getX(batch, xF, xR, xC, d1 + 2),
                               getX(batch, xF, xR, xC, d1 + 3));
                            `:`let xValues = vec4<f32>(
                               getX(batch, d1, xF, xR, xC),
                               getX(batch, d1 + 1, xF, xR, xC),
                               getX(batch, d1 + 2, xF, xR, xC),
                               getX(batch, d1 + 3, xF, xR, xC));
                            `}
                            let wValues = vec4<f32>(
                              getW(d2, d1, wF, wR, wC),
                              getW(d2, d1 + 1, wF, wR, wC),
                              getW(d2, d1 + 2, wF, wR, wC),
                              getW(d2, d1 + 3, wF, wR, wC));
                      value += dot(xValues, wValues);
                    }
                    if (inputDepthVec4Remainder == 1) {
                        ${s?`value += getX(batch, xF, xR, xC, inputDepthNearestVec4)
                          * getW(d2, inputDepthNearestVec4, wF, wR, wC);`:`value += getX(batch, inputDepthNearestVec4, xF, xR, xC)
                          * getW(d2, inputDepthNearestVec4, wF, wR, wC);`}
                    } else if (inputDepthVec4Remainder == 2) {
                      ${s?`let xValues = vec2<f32>(
                        getX(batch, xF, xR, xC, inputDepthNearestVec4),
                        getX(batch, xF, xR, xC, inputDepthNearestVec4 + 1));
                      `:`let xValues = vec2<f32>(
                        getX(batch, inputDepthNearestVec4, xF, xR, xC),
                        getX(batch, inputDepthNearestVec4 + 1, xF, xR, xC));
                    `}
                    let wValues = vec2<f32>(
                      getW(d2, inputDepthNearestVec4, wF, wR, wC),
                      getW(d2, inputDepthNearestVec4 + 1, wF, wR, wC));
                      value += dot(xValues, wValues);
                    } else if (inputDepthVec4Remainder == 3) {
                      ${s?`let xValues = vec3<f32>(
                        getX(batch, xF, xR, xC, inputDepthNearestVec4),
                        getX(batch, xF, xR, xC, inputDepthNearestVec4 + 1),
                        getX(batch, xF, xR, xC, inputDepthNearestVec4 + 2));
                      `:`let xValues = vec3<f32>(
                        getX(batch, inputDepthNearestVec4, xF, xR, xC),
                        getX(batch, inputDepthNearestVec4 + 1, xF, xR, xC),
                        getX(batch, inputDepthNearestVec4 + 2, xF, xR, xC));
                    `}
                    let wValues = vec3<f32>(
                      getW(d2, inputDepthNearestVec4, wF, wR, wC),
                      getW(d2, inputDepthNearestVec4 + 1, wF, wR, wC),
                      getW(d2, inputDepthNearestVec4 + 2, wF, wR, wC));
                      value += dot(xValues, wValues);
                    }
                  }
                }
              }
              ${_?"value = value + getBiasByOutputCoords(coords)":""};
              ${q}
              result[global_idx] = f32(value);
          }`};return{name:"Conv3DNaive",shaderCache:{hint:`${t.cacheKey};${s};${c};${_}`,inputDependencies:g},getRunData:()=>({outputs:[{dims:r,dataType:e[0].dataType}],dispatchGroup:{x:l[0],y:l[1],z:l[2]},programUniforms:m}),getShaderSource:b}}}),oc,uc,Um=P(()=>{ee(),ae(),ne(),Ot(),oc=(e,t,r,a)=>{let n=e.length>2,i=n?"value += b[output_channel];":"",s=e[0].dims,u=e[1].dims,d=t.format==="NHWC",l=d?r[3]:r[1],c=l/t.group,f=d&&c>=4?$e(l):1,m=O.size(r)/f,g=[{type:12,data:m},{type:12,data:t.dilations},{type:12,data:[t.strides[0],t.strides[1]]},{type:12,data:[t.pads[0],t.pads[1]]},{type:12,data:c}];Et(t,g),g.push(...Q(s,[u[0],u[1],u[2],u[3]/f]));let _=n?["rank","rank","rank"]:["rank","rank"];g.push(...Q([r[0],r[1],r[2],r[3]/f]));let b=x=>{let $=H("output",e[0].dataType,r.length,f),w=ke($.type.tensor),S=It(t,$.type.value,w),k=R("x",e[0].dataType,s.length),T=R("w",e[1].dataType,u.length,f),E=[k,T];n&&E.push(R("b",e[2].dataType,e[2].dims,f));let z=[{name:"output_size",type:"u32"},{name:"dilations",type:"u32",length:t.dilations.length},{name:"strides",type:"u32",length:2},{name:"pads",type:"u32",length:2},{name:"output_channels_per_group",type:"u32"}];zt(t,z);let C=d?`
      for (var wHeight: u32 = 0u; wHeight < uniforms.w_shape[0]; wHeight++) {
        let xHeight = xRCCorner.x + wHeight * uniforms.dilations[0];

        if (xHeight < 0u || xHeight >= uniforms.x_shape[1]) {
          continue;
        }

        for (var wWidth: u32 = 0u; wWidth < uniforms.w_shape[1]; wWidth++) {
          let xWidth = xRCCorner.y + wWidth * uniforms.dilations[1];
          if (xWidth < 0u || xWidth >= uniforms.x_shape[2]) {
            continue;
          }

          for (var wInChannel: u32 = 0u; wInChannel < uniforms.w_shape[2]; wInChannel++) {
            let input_channel = in_channel_offset + wInChannel;
            let xVal = ${k.get("batch","xHeight","xWidth","input_channel")};
            let wVal = ${T.get("wHeight","wWidth","wInChannel","output_channel")};
            value += xVal * wVal;
          }
        }
      }
      `:`
      for (var wInChannel: u32 = 0u; wInChannel < uniforms.w_shape[1]; wInChannel++) {
        let input_channel = in_channel_offset + wInChannel;
        for (var wHeight: u32 = 0u; wHeight < uniforms.w_shape[2]; wHeight++) {
          let xHeight = xRCCorner.x + wHeight * uniforms.dilations[0];

          if (xHeight < 0u || xHeight >= uniforms.x_shape[2]) {
            continue;
          }

          for (var wWidth: u32 = 0u; wWidth < uniforms.w_shape[3]; wWidth++) {
            let xWidth = xRCCorner.y + wWidth * uniforms.dilations[1];
            if (xWidth < 0u || xWidth >= uniforms.x_shape[3]) {
              continue;
            }

            let xVal = ${k.get("batch","input_channel","xHeight","xWidth")};
            let wVal = ${T.get("output_channel","wInChannel","wHeight","wWidth")};
            value += xVal * wVal;
          }
        }
      }
      `;return`
  ${x.registerUniforms(z).declareVariables(...E,$)}

  ${x.mainStart()}
    ${x.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}

    let outputIndices = ${$.offsetToIndices("global_idx")};
    let batch: u32 = outputIndices[0];
    let output_channel: u32 = outputIndices[${d?3:1}];
    let xRCCorner: vec2<u32> = vec2<u32>(outputIndices[${d?1:2}], outputIndices[${d?2:3}]) * uniforms.strides - uniforms.pads;
    let group_id: u32 = output_channel * ${f} / uniforms.output_channels_per_group;
    var in_channel_offset = group_id * uniforms.w_shape[${d?2:1}];

    var value: ${$.type.value} = ${$.type.value}(0);
    ${C}
    ${i}
    ${S}
    ${$.setByOffset("global_idx","value")}
  }`};return{name:"GroupedConv",shaderCache:{hint:`${t.cacheKey}_${f}`,inputDependencies:_},getRunData:()=>({outputs:[{dims:a?a(r):r,dataType:e[0].dataType}],dispatchGroup:{x:Math.ceil(m/64)},programUniforms:g}),getShaderSource:b}},uc=(e,t,r,a)=>{let n=e.length>2,i=$e(r[3]),s=$e(r[2]),u=O.size(r)/i/s,d=[e[0].dims[0],e[0].dims[1],e[0].dims[2],e[0].dims[3]/i],l=[e[1].dims[0],e[1].dims[1],e[1].dims[2],e[1].dims[3]/i],c=[r[0],r[1],r[2],r[3]/i],f=[{type:12,data:u},{type:6,data:[t.strides[0],t.strides[1]]},{type:6,data:[t.pads[0],t.pads[1]]}];Et(t,f),f.push(...Q(d,l,c));let m=(s-1)*t.strides[1]+l[1],g=_=>{let b=H("output",e[0].dataType,c.length,i),x=ke(b.type.tensor),$=It(t,b.type.value,x),w=R("x",e[0].dataType,d.length,i),S=R("w",e[1].dataType,l.length,i),k=[w,S];n&&k.push(R("b",e[2].dataType,e[2].dims,i));let T=n?"value += b[output_channel];":"",E=[{name:"output_size",type:"u32"},{name:"strides",type:"i32",length:2},{name:"pads",type:"i32",length:2}];return zt(t,E),`
  ${_.registerUniforms(E).declareVariables(...k,b)}
  ${_.mainStart()}
    ${_.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}
    let width0 = uniforms.output_shape[3];
    let output_channel = global_idx % width0;
    var index1 = global_idx / width0;
    let width1 = uniforms.output_shape[2] / ${s}u;
    let col = (index1 % width1) * ${s}u;
    index1 = index1 / width1;
    let row = index1 % uniforms.output_shape[1];
    let batch = index1 / uniforms.output_shape[1];

    let x_corner = vec2<i32>(i32(row), i32(col)) * uniforms.strides - uniforms.pads;

    var x_vals: array<${w.type.value}, ${m}>;
    var values: array<${b.type.value}, ${s}>;
    let input_channel = output_channel;
    // Use constant instead of uniform can give better performance for w's height/width.
    for (var w_height: u32 = 0u; w_height < ${l[0]}; w_height++) {
      let x_height = x_corner.x + i32(w_height);
      if (x_height >= 0 && u32(x_height) < uniforms.x_shape[1]) {
        for (var i = 0; i < ${m}; i++) {
          let x_width = x_corner.y + i;
          if (x_width >= 0 && u32(x_width) < uniforms.x_shape[2]) {
            x_vals[i] = ${w.get("batch","u32(x_height)","u32(x_width)","input_channel")};
          } else {
            x_vals[i] = ${w.type.value}(0);
          }
        }
        for (var w_width: u32 = 0u; w_width < ${l[1]}; w_width++) {
          let w_val = ${S.get("w_height","w_width","0","output_channel")};
          for (var i = 0u; i < ${s}u; i++) {
            values[i] = fma(x_vals[i * u32(uniforms.strides[1]) + w_width], w_val, values[i]);
          }
        }
      }
    }

    for (var i = 0u; i < ${s}u; i++) {
      var value = values[i];
      ${T}
      ${$}
      ${b.set("batch","row","col + i","output_channel","value")};
    }
  }`};return{name:"GroupedConv-Vectorize",shaderCache:{hint:`${t.cacheKey};${i};${s};${m};${l[0]};${l[1]}`,inputDependencies:n?["rank","rank","type"]:["rank","rank"]},getRunData:()=>({outputs:[{dims:a?a(r):r,dataType:e[0].dataType}],dispatchGroup:{x:Math.ceil(u/64)},programUniforms:f}),getShaderSource:g}}}),Qo,Ir,Xo,Er,xa,Pi,Yo,Jo,ka,qm=P(()=>{ae(),Dm(),Pm(),Za(),Um(),Ot(),Ka(),gt(),Qo=(e,t,r,a,n,i)=>{let s=e[0],u=e.slice(i?1:2,i?3:4),d=u.length,l=t[0],c=t.slice(2).map((m,g)=>m+(m-1)*(r[g]-1)),f=u.map((m,g)=>m+a[g]+a[g+d]).map((m,g)=>Math.floor((m-c[g]+n[g])/n[g]));return f.splice(0,0,s),f.splice(i?3:1,0,l),f},Ir=[2,3,1,0],Xo=(e,t)=>{if(!e||e.length!==2&&e.length!==3)throw new Error("Conv requires 2 or 3 inputs");if(e[0].dims.length>5)throw new Error("greater than 5D is not supported");if(e[0].dims.length!==e[1].dims.length)throw new Error("filter does not have same dimension as input");let r=e[0].dims[t.format==="NHWC"?e[0].dims.length-1:1],a=e[1].dims[1]*t.group;if(r!==a)throw new Error("FILTER_IN_CHANNEL should be equal to DATA_CHANNEL");if(e.length===3&&(e[2].dims.length!==1||e[1].dims[0]!==e[2].dims[0]))throw new Error("invalid bias");let n=e[0].dims.length-2;if(t.dilations.length!==n)throw new Error(`dilations should be ${n}D`);if(t.strides.length!==n)throw new Error(`strides should be ${n}D`);if(t.pads.length!==n*2)throw new Error(`pads should be ${n*2}D`);if(t.kernelShape.length!==0&&t.kernelShape.length!==e[1].dims.length-2)throw new Error("invalid kernel shape")},Er=(e,t)=>{let r=e.kernelShape.slice();r.length<t[1].dims.length-2&&r.push(...Array(t[1].dims.length-2-r.length).fill(0));for(let i=2;i<t[1].dims.length;++i)r[i-2]===0&&(r[i-2]=t[1].dims[i]);let a=e.pads.slice();Pr.adjustPadsBasedOnAutoPad(t[0].dims,e.strides,e.dilations,r,a,e.format==="NHWC",e.autoPad);let n=Object.assign({},e);return Object.assign(n,{kernelShape:r,pads:a}),n},xa=e=>{let t=Ha(e),r=e.format,a=["NOTSET","VALID","SAME_UPPER","SAME_LOWER"][e.auto_pad],n=e.dilations,i=e.group,s=e.kernel_shape,u=e.pads,d=e.strides,l=e.w_is_const();return{autoPad:a,format:r,dilations:n,group:i,kernelShape:s,pads:u,strides:d,wIsConst:l,...t,cacheKey:`${e.format};${t.activation};`}},Pi=(e,t,r,a)=>{let n=r.format==="NHWC",i=Qo(t[0].dims,t[1].dims,r.dilations,r.pads,r.strides,n);if(r.group!==1){let E=[t[0]];if(n){let z=e.kernelCustomData.wT??e.compute(Me(t[1],Ir),{inputs:[1],outputs:[r.wIsConst?-2:-1]})[0];r.wIsConst&&!e.kernelCustomData.wT&&(e.kernelCustomData.wT=z),E.push(z)}else E.push(t[1]);t.length===3&&E.push(t[2]),!e.adapterInfo.isArchitecture("ampere")&&n&&t[1].dims[0]===r.group&&t[1].dims[1]===1&&r.dilations[0]===1&&r.dilations[1]===1?e.compute(uc(E,r,i,a),{inputs:E}):e.compute(oc(E,r,i,a),{inputs:E});return}let s=t.length===3,u=t[0].dims[n?1:2],d=t[0].dims[n?2:3],l=t[0].dims[n?3:1],c=t[1].dims[2],f=t[1].dims[3],m=i[n?1:2],g=i[n?2:3],_=i[n?3:1],b=n&&c===u&&f===d&&r.pads[0]===0&&r.pads[1]===0;if(b||c===1&&f===1&&r.dilations[0]===1&&r.dilations[1]===1&&r.strides[0]===1&&r.strides[1]===1&&r.pads[0]===0&&r.pads[1]===0){let E=i[0],z,C,A,q=[];if(n){let Z=e.kernelCustomData.wT??e.compute(Me(t[1],Ir),{inputs:[1],outputs:[r.wIsConst?-2:-1]})[0];if(r.wIsConst&&!e.kernelCustomData.wT&&(e.kernelCustomData.wT=Z),b){let oe=u*d*l;z=t[0].reshape([1,E,oe]),C=Z.reshape([1,oe,_]),A=[1,E,_]}else z=t[0].reshape([E,u*d,l]),C=Z.reshape([1,l,_]),A=[E,m*g,_];q.push(z),q.push(C)}else z=t[0].reshape([E,l,u*d]),C=t[1].reshape([1,_,l]),A=[E,_,m*g],q.push(C),q.push(z);s&&q.push(t[2]);let X=A[2],G=q[0].dims[q[0].dims.length-1];X<8&&G<8?e.compute(ja(q,r,i,A,n,a),{inputs:q}):e.compute(qr(q,r,i,A,n,a),{inputs:q});return}let x=!0,$=e.kernelCustomData.wT??e.compute(Me(t[1],Ir),{inputs:[1],outputs:[r.wIsConst?-2:-1]})[0];r.wIsConst&&!e.kernelCustomData.wT&&(e.kernelCustomData.wT=$);let w=[t[0],$];s&&w.push(t[2]);let S=n?m*g:_,k=n?_:m*g,T=c*f*l;e.compute(ac(w,r,i,S,k,T,s,x,a),{inputs:w})},Yo=(e,t)=>{let r=t.format==="NHWC",a=[e.inputs[0].reshape(r?[e.inputs[0].dims[0],1,e.inputs[0].dims[1],e.inputs[0].dims[2]]:[e.inputs[0].dims[0],e.inputs[0].dims[1],1,e.inputs[0].dims[2]]),e.inputs[1].reshape([e.inputs[1].dims[0],e.inputs[1].dims[1],1,e.inputs[1].dims[2]])];e.inputs.length===3&&a.push(e.inputs[2]);let n=[0,t.pads[0],0,t.pads[1]],i=[1].concat(t.strides),s=[1].concat(t.dilations),u=[1].concat(t.kernelShape),d=Er({...t,pads:n,strides:i,dilations:s,kernelShape:u},a);Pi(e,a,d,l=>r?[l[0],l[2],l[3]]:[l[0],l[1],l[3]])},Jo=(e,t,r)=>{let a=r.format==="NHWC"?"channelsLast":"channelsFirst",n=Er(r,t),i=r.autoPad==="NOTSET"?r.pads:r.autoPad,s=nc(t[0].dims,t[1].dims,r.strides,r.dilations,i,!1,a);e.compute(sc(t,n,s.outShape,[s.filterDepth,s.filterHeight,s.filterWidth],[s.padInfo.front,s.padInfo.top,s.padInfo.left],a))},ka=(e,t)=>{if(Xo(e.inputs,t),e.inputs[0].dims.length===3)Yo(e,t);else if(e.inputs[0].dims.length===5)Jo(e,e.inputs,t);else{let r=Er(t,e.inputs);Pi(e,e.inputs,r)}}}),lc,Wm=P(()=>{ee(),nt(),ae(),ne(),lc=(e,t,r)=>{let a=e.length>2,n=t.outputShape,i=t.format==="NHWC",s=t.group,u=e[1].dims,d=u[2]/s,l=u[3],c=i?$e(d):1,f=i&&l===1&&d>=4,m=f?Math.floor(d/4)*4:Math.floor(d/c)*c,g=d-m,_=i?$e(l):1,b=i?l===1?c:_:1,x=O.size(n)/_,$=[Math.ceil(x/64),1,1];ue("verbose",()=>`[conv2d_backprop_webgpu] dispatch = ${$}`);let w=["rank","rank"],S=[t.strides[0],t.strides[1]],k=[t.kernelShape[i?1:2],t.kernelShape[i?2:3]],T=[t.dilations[0],t.dilations[1]],E=[k[0]+(t.dilations[0]<=1?0:(t.kernelShape[i?1:2]-1)*(t.dilations[0]-1)),k[1]+(t.dilations[1]<=1?0:(t.kernelShape[i?2:3]-1)*(t.dilations[1]-1))],z=[E[0]-1-Math.floor((t.pads[0]+t.pads[2])/2),E[1]-1-Math.floor((t.pads[1]+t.pads[3])/2)],C=[{type:12,data:x},{type:12,data:S},{type:12,data:k},{type:12,data:T},{type:12,data:E},{type:6,data:z},{type:12,data:m},{type:12,data:d},{type:12,data:l},...Q(e[0].dims,e[1].dims)];a&&(C.push(...Q(e[2].dims)),w.push("rank")),C.push(...Q(n));let A=q=>{let X=[{name:"output_size",type:"u32"},{name:"strides",type:"u32",length:S.length},{name:"filter_dims",type:"u32",length:k.length},{name:"dilations",type:"u32",length:k.length},{name:"effective_filter_dims",type:"u32",length:E.length},{name:"pads",type:"i32",length:z.length},{name:"input_channels_per_group_int",type:"u32"},{name:"input_channels_per_group",type:"u32"},{name:"output_channels_per_group",type:"u32"}],G=ke(e[0].dataType),Z=i?1:2,oe=i?2:3,re=i?3:1,L=R("W",e[1].dataType,e[1].dims.length,b),ie=R("Dy",e[0].dataType,e[0].dims.length,c),F=[ie,L];a&&F.push(R("bias",e[2].dataType,[n[re]].length,_));let Y=H("result",e[0].dataType,n.length,_),ye=()=>{let V="";if(f)c===4?V+=`
        let xValue = ${ie.getByOffset("x_offset")};
        let wValue = ${L.getByOffset("w_offset")};
        dotProd = dotProd + dot(xValue, wValue);
        x_offset += 1u;
        w_offset += 1u;`:c===2?V+=`
          dotProd = dotProd + dot(vec4<${G}>(${ie.getByOffset("x_offset")}, ${ie.getByOffset("x_offset + 1u")}), vec4<${G}>(${L.getByOffset("w_offset")}, ${L.getByOffset("w_offset + 1u")}));
          x_offset += 2u;
          w_offset += 2u;`:c===1&&(V+=`
          dotProd = dotProd + dot(vec4<${G}>(${ie.getByOffset("x_offset")}, ${ie.getByOffset("x_offset + 1u")}, ${ie.getByOffset("x_offset + 2u")}, ${ie.getByOffset("x_offset + 3u")}), vec4<${G}>(${L.getByOffset("w_offset")}, ${L.getByOffset("w_offset + 1u")}, ${L.getByOffset("w_offset + 2u")}, ${L.getByOffset("w_offset + 3u")}));
          x_offset += 4u;
          w_offset += 4u;`);else if(V+=`
                  let xValue = ${i?ie.getByOffset(`${ie.indicesToOffset(`${ie.type.indices}(batch, idyR, idyC, inputChannel)`)} / ${c}`):ie.get("batch","inputChannel","idyR","idyC")};
        `,c===1)V+=`
          let w_offset = ${L.indicesToOffset(`${L.type.indices}(u32(wRPerm), u32(wCPerm), inputChannel, wOutChannel)`)};
          let wValue = ${L.getByOffset(`w_offset / ${b}`)};
          dotProd = dotProd + xValue * wValue;`;else for(let te=0;te<c;te++)V+=`
            let wValue${te} = ${L.getByOffset(`${L.indicesToOffset(`${L.type.indices}(u32(wRPerm), u32(wCPerm), inputChannel + ${te}, wOutChannel)`)} / ${b}`)};
            dotProd = dotProd + xValue[${te}] * wValue${te};`;return V},N=()=>{if(g===0)return"";if(!f)throw new Error(`packInputAs4 ${f} is not true.`);let V="";if(c===1){V+="dotProd = dotProd";for(let te=0;te<g;te++)V+=`
            + ${ie.getByOffset(`x_offset + ${te}`)} * ${L.getByOffset(`w_offset + ${te}`)}`;V+=";"}else if(c===2){if(g!==2)throw new Error(`Invalid inputChannelsRemainder ${g}.`);V+=`
          let xValue = ${ie.getByOffset("x_offset")};
          let wValue = ${L.getByOffset("w_offset")};
          dotProd = dotProd + dot(xValue, wValue);`}return V},U=`
            let outputIndices = ${Y.offsetToIndices(`global_idx * ${_}`)};
            let batch = ${Y.indicesGet("outputIndices",0)};
            let d1 = ${Y.indicesGet("outputIndices",re)};
            let r = ${Y.indicesGet("outputIndices",Z)};
            let c = ${Y.indicesGet("outputIndices",oe)};
            let dyCorner = vec2<i32>(i32(r), i32(c)) - uniforms.pads;
            let dyRCorner = dyCorner.x;
            let dyCCorner = dyCorner.y;
            let groupId = d1 / uniforms.output_channels_per_group;
            let wOutChannel = d1 - groupId * uniforms.output_channels_per_group;
            // Convolve dy(?, ?, d2) with w(:, :, d1, d2) to compute dx(xR, xC, d1).
            // ? = to be determined. : = across all values in that axis.
            var dotProd = ${Y.type.value}(0.0);
            var wR: u32 = 0;
            if (uniforms.dilations.x == 1) {
              // Minimum wR >= 0 that satisfies (dyRCorner + wR) % (uniforms.strides.x) == 0
              wR = u32(((dyRCorner + i32(uniforms.strides.x) - 1) / i32(uniforms.strides.x)) * i32(uniforms.strides.x) - dyRCorner);
            }
            for (; wR < uniforms.effective_filter_dims.x; wR = wR + 1) {
              if (wR % uniforms.dilations.x != 0) {
                continue;
              }
              let dyR = (${G}(dyRCorner) + ${G}(wR)) / ${G}(uniforms.strides[0]);
              let wRPerm = uniforms.filter_dims.x - 1 - wR / uniforms.dilations.x;
              if (dyR < 0.0 || dyR >= ${G}(uniforms.Dy_shape[${Z}]) || fract(dyR) > 0.0 ||
                  wRPerm < 0) {
                continue;
              }
              let idyR: u32 = u32(dyR);
              var wC: u32 = 0;
              if (uniforms.dilations.y == 1) {
                // Minimum wC >= 0 that satisfies (dyCCorner + wC) % (uniforms.strides.y) == 0
                wC = u32(((dyCCorner + i32(uniforms.strides.y) - 1) / i32(uniforms.strides.y)) * i32(uniforms.strides.y) - dyCCorner);
              }
              for (; wC < uniforms.effective_filter_dims.y; wC = wC + 1) {
                if (wC % uniforms.dilations.y != 0) {
                  continue;
                }
                let dyC = (${G}(dyCCorner) + ${G}(wC)) / ${G}(uniforms.strides.y);
                let wCPerm = uniforms.filter_dims.y - 1 - wC / uniforms.dilations.y;
                if (dyC < 0.0 || dyC >= ${G}(uniforms.Dy_shape[${oe}]) ||
                    fract(dyC) > 0.0 || wCPerm < 0) {
                  continue;
                }
                let idyC: u32 = u32(dyC);
                var inputChannel = groupId * uniforms.input_channels_per_group;
                ${f?`
                var x_offset = ${ie.indicesToOffset(`${ie.type.indices}(batch, idyR, idyC, inputChannel)`)} / ${c};
                var w_offset = ${L.indicesToOffset(`${L.type.indices}(wRPerm, wCPerm, inputChannel, wOutChannel)`)} / ${b};
                  `:""}
                for (var d2: u32 = 0; d2 < uniforms.input_channels_per_group_int; d2 = d2 + ${f?4:c}) {
                  ${ye()}
                  inputChannel = inputChannel + ${f?4:c};
                }
                ${N()}
                wC = wC + uniforms.strides.y - 1;
              }
              wR = wR + uniforms.strides[0] - 1;
            }
            let value = dotProd${a?` + bias[d1 / ${_}]`:""};
            ${Y.setByOffset("global_idx","value")};
          `;return`
    ${q.registerUniforms(X).declareVariables(...F,Y)}
      ${q.mainStart()}
      ${q.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")};
    ${U}}`};return{name:"ConvTranspose2D",shaderCache:{hint:`${t.cacheKey};${c}${b}${_}${f}${g}`,inputDependencies:w},getRunData:()=>({dispatchGroup:{x:$[0],y:$[1],z:$[2]},outputs:[{dims:r?r(n):n,dataType:e[0].dataType}],programUniforms:C}),getShaderSource:A}}}),eu,tu,ru,Ui,dc,iu,qi,au,pc,Vm=P(()=>{Wm(),Ot(),gt(),eu=(e,t,r,a,n,i)=>(e-1)*t+r+(a-1)*n+1-i,tu=(e,t,r,a,n)=>{let i=Math.floor(e/2);t==="SAME_UPPER"?(r[a]=i,r[n]=e-i):t==="SAME_LOWER"&&(r[a]=e-i,r[n]=i)},ru=(e,t,r,a,n,i,s,u,d,l)=>{let c=e.length-2,f=l.length===0;d.length<c&&d.push(...Array(c-d.length).fill(0));let m=e[0],g=t[u?3:1]*n;for(let _=0,b=e.length-c-(u?1:0);_<c;++_,++b){let x=e[b],$=f?x*s[_]:l[_],w=eu(x,s[_],i[_],t[b],r[_],$);tu(w,a,i,_,_+c),f&&l.push(s[_]*(x-1)+d[_]+(t[b]-1)*r[_]+1-i[_]-i[_+c])}l.splice(0,0,m),l.splice(u?3:1,0,g)},Ui=(e,t)=>{let r=e.kernelShape.slice();if(e.kernelShape.length===0||e.kernelShape.reduce((f,m)=>f*m,1)===0){r.length=0;for(let f=2;f<t[1].dims.length;++f)r.push(t[1].dims[f])}let a=e.format==="NHWC";r.splice(0,0,t[1].dims[0]),r.splice(a?3:1,0,t[1].dims[1]);let n=e.pads.slice(),i=e.outputShape.slice(),s=e.outputPadding.slice(),u=t[0].dims,d=e.dilations.slice();if(d.reduce((f,m)=>f+m,0)===0){let f=t[0].dims.length-2;d=new Array(f).fill(1)}let l=e.strides.slice();if(l.reduce((f,m)=>f+m,0)===0){let f=t[0].dims.length-2;l=new Array(f).fill(1)}ru(u,r,d,e.autoPad,e.group,n,l,a,s,i);let c=Object.assign({},e);return Object.assign(c,{kernelShape:r,pads:n,outputPadding:s,outputShape:i,dilations:d,strides:l}),c},dc=e=>{let t=Ha(e),r=e.format,a=["NOTSET","VALID","SAME_UPPER","SAME_LOWER"][typeof e.autoPad>"u"?0:e.autoPad],n=e.dilations,i=e.group,s=e.kernelShape,u=e.pads,d=e.strides,l=e.wIsConst(),c=e.outputPadding,f=e.outputShape;return{autoPad:a,format:r,dilations:n,group:i,kernelShape:s,outputPadding:c,outputShape:f,pads:u,strides:d,wIsConst:l,...t,cacheKey:`${e.format};${t.activation};`}},iu=(e,t)=>{if(!e||e.length!==2&&e.length!==3)throw new Error("Conv requires 2 or 3 inputs");if(e[0].dims.length!==4&&e[0].dims.length!==3)throw new Error("currently only support 2-dimensional conv");if(e[0].dims.length!==e[1].dims.length)throw new Error("filter does not have same dimension as input");let r=e[0].dims[t.format==="NHWC"?e[0].dims.length-1:1],a=e[1].dims[0];if(r!==a)throw new Error("FILTER_IN_CHANNEL should be equal to DATA_CHANNEL");let n=e[1].dims[1]*t.group;if(e.length===3&&(e[2].dims.length!==1||e[2].dims[0]!==n))throw new Error("invalid bias");let i=e[0].dims.length-2;if(t.dilations.reduce((s,u)=>s+u,0)>0&&t.dilations.length!==i)throw new Error(`dilations should be ${i}D`);if(t.strides.reduce((s,u)=>s+u,0)>0&&t.strides.length!==i)throw new Error(`strides should be ${i}D`);if(t.pads.reduce((s,u)=>s+u,0)>0&&t.pads.length!==i*2)throw new Error(`pads should be ${i*2}D`);if(t.outputPadding.length!==i&&t.outputPadding.length!==0)throw new Error(`output_padding should be ${i}D`);if(t.kernelShape.reduce((s,u)=>s+u,0)>0&&t.kernelShape.length!==0&&t.kernelShape.length!==e[1].dims.length-2)throw new Error("invalid kernel shape");if(t.outputShape.length!==0&&t.outputShape.length!==e[0].dims.length-2)throw new Error("invalid output shape")},qi=(e,t,r,a)=>{let n=e.kernelCustomData.wT??e.compute(Me(t[1],[2,3,0,1]),{inputs:[1],outputs:[r.wIsConst?-2:-1]})[0];r.wIsConst&&!e.kernelCustomData.wT&&(e.kernelCustomData.wT=n);let i=[t[0],n];t.length===3&&i.push(t[2]),e.compute(lc(i,r,a),{inputs:i})},au=(e,t)=>{let r=t.format==="NHWC",a=[e.inputs[0].reshape(r?[e.inputs[0].dims[0],1,e.inputs[0].dims[1],e.inputs[0].dims[2]]:[e.inputs[0].dims[0],e.inputs[0].dims[1],1,e.inputs[0].dims[2]]),e.inputs[1].reshape([e.inputs[1].dims[0],e.inputs[1].dims[1],1,e.inputs[1].dims[2]])];e.inputs.length===3&&a.push(e.inputs[2]);let n=t.kernelShape;(n.length===0||n[0]===0)&&(n=[e.inputs[1].dims[2]]);let i=t.dilations;(i.length===0||i[0]===0)&&(i=[1]);let s=t.strides;(s.length===0||s[0]===0)&&(s=[1]);let u=t.pads;u.length===0&&(u=[0,0]),u=[0,u[0],0,u[1]],s=[1].concat(s),i=[1].concat(i),n=[1].concat(n);let d=t.outputPadding;d=[0].concat(d);let l=Ui({...t,pads:u,strides:s,dilations:i,kernelShape:n,outputPadding:d},a);qi(e,a,l,c=>r?[c[0],c[2],c[3]]:[c[0],c[1],c[3]])},pc=(e,t)=>{if(iu(e.inputs,t),e.inputs[0].dims.length===3)au(e,t);else{let r=Ui(t,e.inputs);qi(e,e.inputs,r)}}}),nu,cc,fc,Lm=P(()=>{ee(),ae(),ve(),ne(),nu=(e,t,r,a)=>{let n=O.size(t),i=t.length,s=R("input",e,i),u=H("output",e,i),d=r.dataType===6?r.getInt32Array()[0]:Number(r.getBigInt64Array()[0]),l=O.normalizeAxis(d,i),c=f=>{let m=` i32(${s.indicesGet("inputIndices","uniforms.axis")}) `,g=j("uniforms.input_shape","uniforms.axis",i),_=a.reverse?m+(a.exclusive?" + 1":""):"0",b=a.reverse?g:m+(a.exclusive?"":" + 1");return`
                ${f.registerUniform("outputSize","u32").registerUniform("axis","u32").declareVariables(s,u)}
                ${f.mainStart()}
                  ${f.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.outputSize")}
                  var inputIndices = ${u.offsetToIndices("global_idx")};
                  var sum = ${u.type.value}(0);
                  let first : i32 = ${_};
                  let last : i32 = ${b};
                  for (var i : i32 = first; i < last; i++) {
                    ${s.indicesSet("inputIndices","uniforms.axis","u32(i)")};
                    sum = sum + ${s.getByIndices("inputIndices")};
                  }
                  ${u.setByOffset("global_idx","sum")};
                }`};return{name:"CumSum",shaderCache:{hint:a.cacheKey,inputDependencies:["rank"]},getRunData:()=>({outputs:[{dims:t,dataType:e}],dispatchGroup:{x:Math.ceil(n/64)},programUniforms:[{type:12,data:n},{type:12,data:l},...Q(t,t)]}),getShaderSource:c}},cc=(e,t)=>{let r=e.inputs[0].dims,a=e.inputs[0].dataType,n=e.inputs[1];e.compute(nu(a,r,n,t),{inputs:[0]})},fc=e=>{let t=e.exclusive===1,r=e.reverse===1;return pe({exclusive:t,reverse:r})}}),su,ou,uu,hc,mc,Gm=P(()=>{ee(),ae(),ve(),ne(),su=e=>{if(!e||e.length!==1)throw new Error("DepthToSpace requires 1 input.");if(e[0].dims.length!==4)throw new Error("DepthToSpace requires 4D input.")},ou=(e,t,r,a)=>{let n=[];n.push(`fn perm(i: ${a.type.indices}) -> ${r.type.indices} {
    var a: ${r.type.indices};`);for(let i=0;i<t;++i)n.push(r.indicesSet("a",e[i],`i[${i}]`));return n.push("return a;}"),n.join(`
`)},uu=(e,t)=>{let r,a,n,i,s,u,d=t.format==="NHWC",l=t.blocksize,c=t.mode==="DCR";d?([r,a,n,i]=e.dims,s=c?[r,a,n,l,l,i/l**2]:[r,a,n,i/l**2,l,l],u=c?[0,1,3,2,4,5]:[0,1,4,2,5,3]):([r,a,n,i]=[e.dims[0],e.dims[2],e.dims[3],e.dims[1]],s=c?[r,l,l,i/l**2,a,n]:[r,i/l**2,l,l,a,n],u=c?[0,3,4,1,5,2]:[0,1,4,2,5,3]);let f=e.reshape(s),m=f.dims.length,g=e.dataType,_=R("a",g,m),b=H("output",g,m),x=$=>`
  ${$.registerUniform("output_size","u32").declareVariables(_,b)}

  ${ou(u,m,_,b)}

  ${$.mainStart()}
    ${$.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}

    let indices = ${b.offsetToIndices("global_idx")};
    let aIndices = perm(indices);

    ${b.setByOffset("global_idx",_.getByIndices("aIndices"))}
  }`;return{name:"DepthToSpace",shaderCache:{hint:`${e.dims};${t.blocksize};${t.mode}`,inputDependencies:["rank"]},getRunData:$=>{let w=d?[r,a*l,n*l,i/l**2]:[r,i/l**2,a*l,n*l],S=O.size(w),k=f.dims,T=O.sortBasedOnPerm(k,u);return{outputs:[{dims:w,dataType:$[0].dataType}],dispatchGroup:{x:Math.ceil(S/64)},programUniforms:[{type:12,data:S},...Q(k,T)]}},getShaderSource:x}},hc=(e,t)=>{su(e.inputs),e.compute(uu(e.inputs[0],t))},mc=e=>pe({blocksize:e.blocksize,mode:e.mode,format:e.format})}),zr,Qt,Wi,lu,du,pu,cu,Vi,fu,gc,_c,Hm=P(()=>{ee(),ae(),ve(),ne(),zr="[a-zA-Z]|\\.\\.\\.",Qt="("+zr+")+",Wi="^"+Qt+"$",lu="("+Qt+",)*"+Qt,du="^"+lu+"$",pu=class{constructor(e=-1){this.symbolToIndices=new Map,this.inputIndex=e}addSymbol(e,t){let r=this.symbolToIndices.get(e);r===void 0?r=[t]:r.push(t),this.symbolToIndices.set(e,r)}},cu=class{constructor(e,t){var n;this.equation=t,this.hasEllipsis=!1,this.symbolToInfo=new Map,this.lhs=new Array,this.outputDims=[];let[r,a]=t.includes("->")?t.split("->",2):[t,""];if(!r.match(RegExp(du)))throw new Error("Invalid LHS term");if(r.split(",").forEach((i,s)=>{let u=e[s].dims.slice();if(!i.match(RegExp(Wi)))throw new Error("Invalid LHS term");let d=this.processTerm(i,!0,u,s);this.lhs.push(d)}),a==="")a+=[...this.symbolToInfo.entries()].filter(([i,s])=>s.count===1||i==="...").map(([i])=>i).join("");else if(!a.match(RegExp(Qt)))throw new Error("Invalid RHS");(n=a.match(RegExp(zr,"g")))==null||n.forEach(i=>{if(i==="...")this.outputDims=this.outputDims.concat(this.ellipsisDims);else{let s=this.symbolToInfo.get(i);if(s===void 0)throw new Error("Invalid RHS symbol");this.outputDims.push(s.dimValue)}}),this.rhs=this.processTerm(a,!1,this.outputDims)}addSymbol(e,t,r){let a=this.symbolToInfo.get(e);if(a!==void 0){if(a.dimValue!==t&&a.count!==1)throw new Error("Dimension mismatch");a.count++,a.inputIndices.push(r)}else a={count:1,dimValue:t,inputIndices:[r]};this.symbolToInfo.set(e,a)}processTerm(e,t,r,a=-1){let n=r.length,i=!1,s=[],u=0;if(!e.match(RegExp(Wi))&&!t&&e!=="")throw new Error("Invalid LHS term");let d=e.match(RegExp(zr,"g")),l=new pu(a);return d==null||d.forEach((c,f)=>{if(c==="..."){if(i)throw new Error("Only one ellipsis is allowed per input term");i=!0;let m=n-d.length+1;if(m<0)throw new Error("Ellipsis out of bounds");if(s=r.slice(u,u+m),this.hasEllipsis){if(this.ellipsisDims.length!==s.length||this.ellipsisDims.toString()!==s.toString())throw new Error("Ellipsis dimensions mismatch")}else if(t)this.hasEllipsis=!0,this.ellipsisDims=s;else throw new Error("Ellipsis must be specified in the LHS");for(let g=0;g<s.length;g++){let _=String.fromCharCode(48+g);l.addSymbol(_,f+g),this.addSymbol(_,r[u++],a)}}else l.addSymbol(c,f+(this.hasEllipsis?this.ellipsisDims.length-1:0)),this.addSymbol(c,r[u++],a)}),l}},Vi=e=>e+"_max",fu=(e,t,r,a)=>{let n=e.map(l=>l.length).map((l,c)=>R(`input${c}`,t,l)),i=O.size(a),s=H("output",t,a.length),u=[...r.symbolToInfo.keys()].filter(l=>!r.rhs.symbolToIndices.has(l)),d=l=>{let c=[],f="var prod = 1.0;",m="var sum = 0.0;",g="sum += prod;",_=[],b=[],x=[],$=[],w=r.symbolToInfo.size===r.rhs.symbolToIndices.size;r.symbolToInfo.forEach((k,T)=>{var E;if(r.rhs.symbolToIndices.has(T)){let z=(E=r.rhs.symbolToIndices.get(T))==null?void 0:E[0];z!==void 0&&r.lhs.forEach((C,A)=>{if(k.inputIndices.includes(A)){let q=C.symbolToIndices.get(T);if(q===void 0)throw new Error("Invalid symbol error");q.forEach(X=>{c.push(`${n[A].indicesSet(`input${A}Indices`,X,s.indicesGet("outputIndices",z))}`)})}})}else r.lhs.forEach((z,C)=>{if(k.inputIndices.includes(C)){let A=z.symbolToIndices.get(T);if(A===void 0)throw new Error("Invalid symbol error");A.forEach(q=>{_.push(`${n[C].indicesSet(`input${C}Indices`,q,`${T}`)}`)}),$.push(`prod *= ${n[C].getByIndices(`input${C}Indices`)};`)}}),b.push(`for(var ${T}: u32 = 0; ${T} < uniforms.${Vi(T)}; ${T}++) {`),x.push("}")});let S=w?[...c,`let sum = ${n.map((k,T)=>k.getByIndices(`input${T}Indices`)).join(" * ")};`]:[...c,m,...b,..._,f,...$,g,...x];return`
            ${l.registerUniforms(u.map(k=>({name:`${Vi(k)}`,type:"u32"}))).registerUniform("outputSize","u32").declareVariables(...n,s)}

            ${l.mainStart()}
            ${l.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.outputSize")}
            var outputIndices = ${s.offsetToIndices("global_idx")};
            ${n.map((k,T)=>`var input${T}Indices: ${n[T].type.indices};`).join(`
`)}
            ${S.join(`
`)};
            ${s.setByOffset("global_idx","sum")};
          }`};return{name:"Einsum",shaderCache:{hint:r.equation,inputDependencies:e.map(()=>"rank")},getRunData:()=>{let l=u.filter(f=>r.symbolToInfo.has(f)).map(f=>{var m;return{type:12,data:((m=r.symbolToInfo.get(f))==null?void 0:m.dimValue)||0}});l.push({type:12,data:i});let c=e.map((f,m)=>[...Q(f)]).reduce((f,m)=>f.concat(m),l);return c.push(...Q(a)),{outputs:[{dims:a,dataType:t}],dispatchGroup:{x:Math.ceil(i/64)},programUniforms:c}},getShaderSource:d}},gc=(e,t)=>{let r=new cu(e.inputs,t.equation),a=r.outputDims,n=e.inputs.map((i,s)=>i.dims);e.compute(fu(n,e.inputs[0].dataType,r,a))},_c=e=>{let t=e.equation.replace(/\s+/g,"");return pe({equation:t})}}),hu,Li,mu,gu,yc,Fm=P(()=>{ee(),ae(),ne(),hu=e=>{if(!e||e.length!==2)throw new Error("Expand requires 2 input.");let t=e[0].dims,r=Array.from(e[1].getBigInt64Array(),Number),a=r.length<t.length?0:r.length-t.length,n=t.length<r.length?0:t.length-r.length;for(;a<r.length&&n<t.length;++a,++n)if(r[a]!==t[n]&&r[a]!==1&&t[n]!==1)throw new Error("Expand requires shape to be broadcastable to input")},Li=(e,t)=>{let r=e.length-t.length,a=[];for(let n=0;n<r;++n)a.push(e[n]);for(let n=0;n<t.length;++n)a.push(t[n]===1?e[n+r]:t[n]);return a},mu=(e,t)=>e.length>t.length?Li(e,t):Li(t,e),gu=e=>{let t=e[0].dims,r=Array.from(e[1].getBigInt64Array(),Number),a=mu(t,r),n=e[0].dataType,i=n===9||O.size(t)===1,s=n===9||t.length>0&&t[t.length-1]%4===0?4:1,u=i||a.length>0&&a[a.length-1]%4===0?4:1,d=Math.ceil(O.size(a)/u),l=f=>{let m=R("input",n,t.length,s),g=H("output",n,a.length,u),_;if(n===9){let b=(x,$,w="")=>`
          let outputIndices${$} = ${g.offsetToIndices(`outputOffset + ${$}u`)};
          let offset${$} = ${m.broadcastedIndicesToOffset(`outputIndices${$}`,g)};
          let index${$} = offset${$} / 4u;
          let component${$} = offset${$} % 4u;
          ${x}[${$}] = ${w}(${m.getByOffset(`index${$}`)}[component${$}]);
        `;_=`
        let outputOffset = global_idx * ${u};
        var data = vec4<u32>(0);
        ${b("data",0,"u32")}
        ${b("data",1,"u32")}
        ${b("data",2,"u32")}
        ${b("data",3,"u32")}
        ${g.setByOffset("global_idx","data")}
      }`}else _=`
        let outputIndices = ${g.offsetToIndices(`global_idx * ${u}`)};
        let inputOffset = ${m.broadcastedIndicesToOffset("outputIndices",g)};
        let data = ${g.type.value}(${m.getByOffset(`inputOffset / ${s}`)});
        ${g.setByOffset("global_idx","data")}
      }`;return`
    ${f.registerUniform("vec_size","u32").declareVariables(m,g)}
    ${f.mainStart()}
    ${f.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.vec_size")}
    ${_}`},c=[{type:12,data:d},...Q(t,a)];return{name:"Expand",shaderCache:{hint:`${a.length};${s}${u}`,inputDependencies:["rank"]},getShaderSource:l,getRunData:()=>({outputs:[{dims:a,dataType:e[0].dataType}],dispatchGroup:{x:Math.ceil(d/64)},programUniforms:c})}},yc=e=>{hu(e.inputs),e.compute(gu(e.inputs),{inputs:[0]})}}),_u,bc,jm=P(()=>{ee(),ae(),ne(),Ga(),_u=e=>{let t=e[0].dataType,r=O.size(e[0].dims),a=O.size(e[1].dims),n=a%4===0,i=s=>{let u=R("x",t,[1],4),d=R("bias",t,[1],4),l=H("y",t,[1],4),c=[{name:"output_vec_size",type:"u32"},{name:"bias_size",type:"u32"}],f=g=>`
      let bias${g}_offset: u32 = (global_idx * 4 + ${g}) % uniforms.bias_size;
      let bias${g} = ${d.getByOffset(`bias${g}_offset / 4`)}[bias${g}_offset % 4];`,m=n?`
      let bias = ${d.getByOffset("global_idx % (uniforms.bias_size / 4)")};`:`${f(0)}${f(1)}${f(2)}${f(3)}
      let bias = ${u.type.value}(bias0, bias1, bias2, bias3);`;return`${s.registerUniforms(c).declareVariables(u,d,l)}

    ${ba(Ee(t))}

    ${s.mainStart(Ut)}
      ${s.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_vec_size")}

      let x = ${u.getByOffset("global_idx")};
      ${m}
      let x_in = x + bias;
      ${l.setByOffset("global_idx",wa("x_in"))}
    }`};return{name:"FastGeluWithBias",shaderCache:{hint:`${n}`,inputDependencies:["type","type"]},getShaderSource:i,getRunData:s=>({outputs:[{dims:s[0].dims,dataType:s[0].dataType}],programUniforms:[{type:12,data:Math.ceil(r/4)},{type:12,data:a}],dispatchGroup:{x:Math.ceil(r/Ut/4)}})}},bc=e=>{e.inputs.length<2||O.size(e.inputs[1].dims)===0?Up(e):e.compute(_u(e.inputs))}}),yu,bu,wc,$c,Km=P(()=>{ee(),ae(),ve(),ne(),yu=e=>{if(!e||e.length!==2)throw new Error("Gather requires 2 inputs.")},bu=(e,t)=>{let r=e[0].dims,a=e[1].dims,n=r.length,i=O.normalizeAxis(t.axis,n),s=r.slice(0);s.splice(i,1,...a);let u=r[i],d=e[0].dataType===9?4:1,l=Math.ceil(O.size(s)/d),c=[{type:12,data:l},{type:6,data:u},{type:12,data:i},...Q(e[0].dims,e[1].dims,s)],f=m=>{let g=R("data",e[0].dataType,e[0].dims.length,d),_=R("inputIndices",e[1].dataType,e[1].dims.length),b=H("output",e[0].dataType,s.length,d),x=w=>{let S=a.length,k=`var indicesIndices${w}  = ${_.type.indices}(0);`;for(let T=0;T<S;T++)k+=`${S>1?`indicesIndices${w}[${T}]`:`indicesIndices${w}`} = ${s.length>1?`outputIndices${w}[uniforms.axis + ${T}]`:`outputIndices${w}`};`;k+=`
          var idx${w} = ${_.getByIndices(`indicesIndices${w}`)};
          if (idx${w} < 0) {
            idx${w} = idx${w} + uniforms.axisDimLimit;
          }
          var dataIndices${w} : ${g.type.indices};
        `;for(let T=0,E=0;T<n;T++)T===i?(k+=`${n>1?`dataIndices${w}[${T}]`:`dataIndices${w}`} = u32(idx${w});`,E+=S):(k+=`${n>1?`dataIndices${w}[${T}]`:`dataIndices${w}`} = ${s.length>1?`outputIndices${w}[${E}]`:`outputIndices${w}`};`,E++);return k},$;if(e[0].dataType===9){let w=(S,k,T="")=>`
          let outputIndices${k} = ${b.offsetToIndices(`outputOffset + ${k}u`)};
          ${x(k)};
          let offset${k} = ${g.indicesToOffset(`dataIndices${k}`)};
          let index${k} = offset${k} / 4u;
          let component${k} = offset${k} % 4u;
          ${S}[${k}] = ${T}(${g.getByOffset(`index${k}`)}[component${k}]);
        `;$=`
        let outputOffset = global_idx * ${d};
        var value = vec4<u32>(0);
        ${w("value",0,"u32")}
        ${w("value",1,"u32")}
        ${w("value",2,"u32")}
        ${w("value",3,"u32")}
        ${b.setByOffset("global_idx","value")}
      `}else $=`
      let outputIndices = ${b.offsetToIndices("global_idx")};
      ${x("")};
      let value = ${g.getByIndices("dataIndices")};
      ${b.setByOffset("global_idx","value")};
      `;return`
      ${m.registerUniform("outputSize","u32").registerUniform("axisDimLimit","i32").registerUniform("axis","u32").declareVariables(g,_,b)}
      ${m.mainStart()}
        ${m.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.outputSize")}
        ${$}
      }`};return{name:"Gather",shaderCache:{hint:t.cacheKey,inputDependencies:["rank","rank"]},getRunData:()=>({outputs:[{dims:s,dataType:e[0].dataType}],dispatchGroup:{x:Math.ceil(l/64)},programUniforms:c}),getShaderSource:f}},wc=e=>pe({axis:e.axis}),$c=(e,t)=>{let r=e.inputs;yu(r),e.compute(bu(e.inputs,t))}}),wu,vc,xc,Zm=P(()=>{ee(),ae(),ne(),wu=(e,t,r,a,n,i,s,u,d)=>{let l=[{type:12,data:i},{type:12,data:a},{type:12,data:n},{type:12,data:r},{type:12,data:s},{type:12,data:u},{type:12,data:d}],c=[i];l.push(...Q(t.dims,c));let f=m=>{let g=R("indices_data",t.dataType,t.dims.length),_=H("input_slice_offsets_data",12,1,1),b=[g,_],x=[{name:"output_size",type:"u32"},{name:"batch_dims",type:"u32"},{name:"input_dims",type:"u32",length:n.length},{name:"sizes_from_slice_dims_data",type:"u32",length:r.length},{name:"num_slices_per_batch",type:"u32"},{name:"input_batch_stride",type:"u32"},{name:"num_slice_dims",type:"u32"}];return`
  ${m.registerUniforms(x).declareVariables(...b)}
  ${m.mainStart()}
    ${m.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}
    let batch_idx = global_idx / uniforms.num_slices_per_batch;
    let base_offset = batch_idx * uniforms.input_batch_stride;

    let slice_indices_base_offset = global_idx * uniforms.num_slice_dims;
    var relative_slice_offset = 0;
    for (var dim_idx = 0u; dim_idx < uniforms.num_slice_dims; dim_idx ++) {
      var index = i32(indices_data[dim_idx + slice_indices_base_offset].x);
      let input_dim_idx = uniforms.batch_dims + dim_idx;
      if (index < 0) {
        ${n.length===1?"index += i32(uniforms.input_dims);":"index += i32(uniforms.input_dims[input_dim_idx]);"}
      }
      ${r.length===1?"relative_slice_offset += index * i32(uniforms.sizes_from_slice_dims_data);":"relative_slice_offset += index * i32(uniforms.sizes_from_slice_dims_data[dim_idx]);"}
    }

    input_slice_offsets_data[global_idx] =  base_offset + u32(relative_slice_offset);
  }`};return e.compute({name:"computeSliceOffsets",shaderCache:{hint:`${n.length}_${r.length}`,inputDependencies:["rank"]},getRunData:()=>({outputs:[{dims:c,dataType:e.inputs[1].dataType}],dispatchGroup:{x:Math.ceil(i/64)},programUniforms:l}),getShaderSource:f},{inputs:[t],outputs:[-1]})[0]},vc=(e,t)=>{let r=e.inputs,a=r[0].dims,n=r[0].dataType,i=r[1].dims,s=i[i.length-1],u=O.sizeToDimension(i,i.length-1),d=O.sizeFromDimension(a,t.batchDims+s),l=O.sizeToDimension(a,t.batchDims),c=O.sizeFromDimension(a,t.batchDims),f=u/l,m=new Array(s),g=d;for(let k=0;k<s;++k)m[s-1-k]=g,g*=a[t.batchDims+s-1-k];let _=wu(e,r[1],m,t.batchDims,a,u,f,c,s),b=t.batchDims+s;if(b>a.length)throw new Error("last dimension of indices must not be larger than rank of input tensor");let x=i.slice(0,-1).concat(a.slice(b)),$=O.size(x),w=[{type:12,data:$},{type:12,data:d},...Q(r[0].dims,_.dims,x)],S=k=>{let T=R("data",r[0].dataType,r[0].dims.length),E=R("slice_offsets",12,_.dims.length),z=H("output",r[0].dataType,x.length);return`
          ${k.registerUniform("output_size","u32").registerUniform("slice_size","u32").declareVariables(T,E,z)}
            ${k.mainStart()}
            ${k.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}
          let slice_offset = slice_offsets[global_idx / uniforms.slice_size];
          output[global_idx] = data[u32(slice_offset) + global_idx % uniforms.slice_size];
        }`};e.compute({name:"GatherND",shaderCache:{hint:t.cacheKey,inputDependencies:["rank","rank"]},getRunData:()=>({outputs:[{dims:x,dataType:n}],dispatchGroup:{x:Math.ceil($/64)},programUniforms:w}),getShaderSource:S},{inputs:[r[0],_]})},xc=e=>({batchDims:e.batch_dims,cacheKey:""})}),$u,vu,kc,Sc,Qm=P(()=>{ee(),ae(),ve(),ne(),$u=(e,t)=>{if(e.length<3||e.length>4)throw new Error("GatherBlockQuantized requires 3 or 4 inputs.");let r=O.normalizeAxis(t.quantizeAxis,e[0].dims.length),a=t.blockSize,n=e[0],i=e[2],s=e.length===4?e[3]:void 0;if(i.dims.length!==n.dims.length||!n.dims.map((u,d)=>d===r?Math.ceil(u/a)===i.dims[d]:u===i.dims[d]).reduce((u,d)=>u&&d,!0))throw new Error("Scales must have the same rank as the input tensor and the dims should match except on gatherAxis.");if(s){if(s.dataType!==n.dataType)throw new Error("Zero point must have the same data type as the input tensor.");if(s.dims.length!==i.dims.length||!s.dims.map((u,d)=>u===i.dims[d]).reduce((u,d)=>u&&d,!0))throw new Error("Zero point must have the same rank as the input tensor and the dims should match except on quantizeAxis.")}},vu=(e,t)=>{let r=e[0].dims,a=e[1].dims,n=r.length,i=O.normalizeAxis(t.gatherAxis,n),s=O.normalizeAxis(t.quantizeAxis,n),u=r.slice(0);u.splice(i,1,...a);let d=O.size(u),l=e[2].dataType,c=e[0].dataType===22,f=[{type:12,data:d},{type:12,data:s},{type:12,data:i},{type:12,data:t.blockSize},...Q(...e.map((g,_)=>g.dims),u)],m=g=>{let _=R("data",e[0].dataType,e[0].dims.length),b=R("inputIndices",e[1].dataType,e[1].dims.length),x=R("scales",e[2].dataType,e[2].dims.length),$=e.length>3?R("zeroPoint",e[3].dataType,e[3].dims.length):void 0,w=H("output",l,u.length),S=[_,b,x];$&&S.push($);let k=[{name:"output_size",type:"u32"},{name:"quantize_axis",type:"u32"},{name:"gather_axis",type:"u32"},{name:"block_size",type:"u32"}];return`
        ${g.registerUniforms(k).declareVariables(...S,w)}
        ${g.mainStart()}
        let output_indices = ${w.offsetToIndices("global_idx")};
        var indices_indices = ${b.type.indices}(0);
        ${a.length>1?`
          for (var i: u32 = 0; i < ${a.length}; i++) {
            let index = ${w.indicesGet("output_indices","uniforms.gather_axis + i")};
            ${b.indicesSet("indices_indices","i","index")};
          }`:`indices_indices = ${w.indicesGet("output_indices","uniforms.gather_axis")};`};
        var data_indices = ${_.type.indices}(0);
        for (var i: u32 = 0; i < uniforms.gather_axis; i++) {
          let index = ${w.indicesGet("output_indices","i")};
          ${_.indicesSet("data_indices","i","index")};
        }
        var index_from_indices = ${b.getByIndices("indices_indices")};
        if (index_from_indices < 0) {
          index_from_indices += ${r[i]};
        }
        ${_.indicesSet("data_indices","uniforms.gather_axis","u32(index_from_indices)")};
        for (var i = uniforms.gather_axis + 1; i < ${u.length}; i++) {
          let index = ${w.indicesGet("output_indices",`i + ${a.length} - 1`)};
          ${_.indicesSet("data_indices","i","index")};
        }
        let data_offset = ${_.indicesToOffset("data_indices")};
        let data_index = data_offset % 8;
        // Convert 4-bit packed data to 8-bit packed data.
        let packed_4bit_quantized_data = ${_.getByOffset("data_offset / 8")};
        let packed_8bit_quantized_data = (packed_4bit_quantized_data >> (4 * (data_index % 2))) & 0x0f0f0f0f;
        let quantized_data_vec = ${c?"unpack4xI8":"unpack4xU8"}(u32(packed_8bit_quantized_data));
        let quantized_data = quantized_data_vec[data_index / 2];
        var scale_indices = data_indices;
        let quantize_axis_index = ${x.indicesGet("data_indices","uniforms.quantize_axis")} / uniforms.block_size;
        ${x.indicesSet("scale_indices","uniforms.quantize_axis","quantize_axis_index")};
        var scale = ${x.getByIndices("scale_indices")};
        ${$?`
              let zero_point_indices = scale_indices;
              let zero_point_offset = ${$.indicesToOffset("zero_point_indices")};
              let zero_point_index = zero_point_offset % 8;
              let packed_4bit_zero_points = ${$.getByOffset("zero_point_offset / 8")};
              let packed_8bit_zero_points = (packed_4bit_zero_points >> (4 * (zero_point_index % 2))) & 0x0f0f0f0f;
              let zero_point_vec = ${c?"unpack4xI8":"unpack4xU8"}(u32(packed_8bit_zero_points));
              let zero_point = zero_point_vec[zero_point_index / 2];`:"var zero_point = 0"};
        let dequantized_data = ${Ee(l)}(quantized_data - zero_point) * scale;
        ${w.setByOffset("global_idx","dequantized_data")};
    }`};return{name:"GatherBlockQuantized",shaderCache:{hint:`${t.cacheKey};${e.filter((g,_)=>_!==1).map(g=>g.dims.join("_")).join(";")}`,inputDependencies:Array.from({length:e.length},(g,_)=>"rank")},getRunData:()=>({outputs:[{dims:u,dataType:l}],dispatchGroup:{x:Math.ceil(d/64)},programUniforms:f}),getShaderSource:m}},kc=(e,t)=>{let r=e.inputs;$u(r,t),e.compute(vu(e.inputs,t))},Sc=e=>pe({blockSize:e.blockSize,gatherAxis:e.gatherAxis,quantizeAxis:e.quantizeAxis})}),xu,ku,Tc,Ic,Xm=P(()=>{ee(),ae(),ve(),ne(),xu=e=>{if(!e||e.length!==2)throw new Error("GatherElements requires 2 inputs.");if(e[0].dims.length<1)throw new Error("GatherElements requires that the data input be rank >= 1.");if(e[0].dims.length!==e[1].dims.length)throw new Error(`GatherElements requires that the data input and
                     indices input tensors be of same rank.`)},ku=(e,t)=>{let r=e[0].dims,a=e[0].dataType,n=r.length,i=e[1].dims,s=e[1].dataType,u=O.normalizeAxis(t.axis,n),d=r[u],l=i.slice(0),c=O.size(l),f=R("input",a,n),m=R("indicesInput",s,i.length),g=H("output",a,l.length),_=[{type:12,data:c},{type:6,data:d},{type:12,data:u}];return _.push(...Q(r,i,l)),{name:"GatherElements",shaderCache:{inputDependencies:["rank","rank"]},getRunData:()=>({outputs:[{dims:l,dataType:e[0].dataType}],dispatchGroup:{x:Math.ceil(c/64)},programUniforms:_}),getShaderSource:b=>`
      ${b.registerUniform("outputSize","u32").registerUniform("axisDimLimit","i32").registerUniform("axis","u32").declareVariables(f,m,g)}
      ${b.mainStart()}
      ${b.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.outputSize")}

      let outputIndices = ${g.offsetToIndices("global_idx")};

      var idx = ${m.getByOffset("global_idx")};
      if (idx < 0) {
        idx = idx + uniforms.axisDimLimit;
      }
      var inputIndices = ${f.type.indices}(outputIndices);
      ${f.indicesSet("inputIndices","uniforms.axis","u32(idx)")};
      let value = ${f.getByIndices("inputIndices")};

      ${g.setByOffset("global_idx","value")};
  }`}},Tc=e=>pe({axis:e.axis}),Ic=(e,t)=>{let r=e.inputs;xu(r),e.compute(ku(e.inputs,t))}}),Su,Tu,Ec,zc,Ym=P(()=>{ee(),ae(),ne(),Su=e=>{if(!e)throw new Error("Input is missing");if(e.length<2||e.length>3)throw new Error("Invaid input number.");if(e.length===3&&e[2].dims.length>2)throw new Error("Invalid input shape of C");if(e[0].dataType!==e[1].dataType||e.length===3&&e[0].dataType!==e[2].dataType)throw new Error("Input types are mismatched")},Tu=(e,t)=>{let r=e[0].dims.slice(),a=e[1].dims.slice(),[n,i,s]=Td.getShapeOfGemmResult(r,t.transA,a,t.transB,e.length===3?e[2].dims:void 0),u=[n,i];if(!u)throw new Error("Can't use gemm on the given tensors");let d=16,l=Math.ceil(i/d),c=Math.ceil(n/d),f=!0,m=O.size(u),g=[{type:12,data:f?l:m},{type:12,data:n},{type:12,data:i},{type:12,data:s},{type:1,data:t.alpha},{type:1,data:t.beta}],_=["type","type"];e.length===3&&(g.push(...Q(e[2].dims)),_.push("rank")),g.push(...Q(u));let b=$=>{let w="";t.transA&&t.transB?w="value += a[k * uniforms.M + m] * b[n * uniforms.K + k];":t.transA&&!t.transB?w="value += a[k * uniforms.M + m] * b[k * uniforms.N + n];":!t.transA&&t.transB?w="value += a[m * uniforms.K + k] * b[n * uniforms.K + k];":!t.transA&&!t.transB&&(w="value += a[m * uniforms.K + k] * b[k * uniforms.N + n];");let S=t.alpha===1?"":"value *= uniforms.alpha;",k=R("a",e[0].dataType,e[0].dims),T=R("b",e[1].dataType,e[1].dims),E=k.type.value,z=null,C=[k,T];e.length===3&&(z=R("c",e[2].dataType,e[2].dims.length),C.push(z));let A=H("output",e[0].dataType,u.length);C.push(A);let q=[{name:"output_size",type:"u32"},{name:"M",type:"u32"},{name:"N",type:"u32"},{name:"K",type:"u32"},{name:"alpha",type:"f32"},{name:"beta",type:"f32"}];return`
  ${$.registerUniforms(q).declareVariables(...C)}

  ${$.mainStart()}
    ${$.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}

    let m = global_idx / uniforms.N;
    let n = global_idx % uniforms.N;

    var value = ${E}(0);
    for (var k: u32 = 0u; k < uniforms.K; k++) {
      ${w}
    }

    ${S}
    ${z!=null?`let cOffset = ${z.broadcastedIndicesToOffset("vec2(m, n)",A)}; value += ${E}(uniforms.beta) * ${z.getByOffset("cOffset")};`:""}
    output[global_idx] = value;
  }`},x=$=>{let w=R("a",e[0].dataType,e[0].dims),S=R("b",e[1].dataType,e[1].dims),k=null,T=[w,S];e.length===3&&(k=R("c",e[2].dataType,e[2].dims.length),T.push(k));let E=H("output",e[0].dataType,u.length);T.push(E);let z=[{name:"num_tile_n",type:"u32"},{name:"M",type:"u32"},{name:"N",type:"u32"},{name:"K",type:"u32"},{name:"alpha",type:"f32"},{name:"beta",type:"f32"}],C="",A="";t.transA&&t.transB?(A=`
      var col = tile_row_start + local_id.x;
      var row = k_start + local_id.y;
      if (col < uniforms.M && row < uniforms.K) {
        tile_a[local_id.y][local_id.x] = a[row * uniforms.M + col];
      } else {
        tile_a[local_id.y][local_id.x] = ${w.type.value}(0);
      }

      col = k_start + local_id.x;
      row = tile_col_start + local_id.y;
      if (col < uniforms.K && row < uniforms.N) {
        tile_b[local_id.y][local_id.x] = b[row * uniforms.K + col];
      } else {
        tile_b[local_id.y][local_id.x] = ${S.type.value}(0);
      }
      `,C="value += tile_a[k][local_id.y] * tile_b[local_id.x][k];"):t.transA&&!t.transB?(A=`
      var col = tile_row_start + local_id.x;
      var row = k_start + local_id.y;
      if (col < uniforms.M && row < uniforms.K) {
        tile_a[local_id.y][local_id.x] = a[row * uniforms.M + col];
      } else {
        tile_a[local_id.y][local_id.x] = ${w.type.value}(0);
      }

      col = tile_col_start + local_id.x;
      row = k_start + local_id.y;
      if (col < uniforms.N && row < uniforms.K) {
        tile_b[local_id.y][local_id.x] = b[row * uniforms.N + col];
      } else {
        tile_b[local_id.y][local_id.x] = ${S.type.value}(0);
      }
      `,C="value += tile_a[k][local_id.y] * tile_b[k][local_id.x];"):!t.transA&&t.transB?(A=`
      var col = k_start + local_id.x;
      var row = tile_row_start + local_id.y;
      if (col < uniforms.K && row < uniforms.M) {
        tile_a[local_id.y][local_id.x] = a[row * uniforms.K + col];
      } else {
        tile_a[local_id.y][local_id.x] = ${w.type.value}(0);
      }

      col = k_start + local_id.x;
      row = tile_col_start + local_id.y;
      if (col < uniforms.K && row < uniforms.N) {
        tile_b[local_id.y][local_id.x] = b[row * uniforms.K + col];
      } else {
        tile_b[local_id.y][local_id.x] = ${S.type.value}(0);
      }
      `,C="value += tile_a[local_id.y][k] * tile_b[local_id.x][k];"):!t.transA&&!t.transB&&(A=`
      var col = k_start + local_id.x;
      var row = tile_row_start + local_id.y;
      if (col < uniforms.K && row < uniforms.M) {
        tile_a[local_id.y][local_id.x] = a[row * uniforms.K + col];
      } else {
        tile_a[local_id.y][local_id.x] = ${w.type.value}(0);
      }

      col = tile_col_start + local_id.x;
      row = k_start + local_id.y;
      if (col < uniforms.N && row < uniforms.K) {
        tile_b[local_id.y][local_id.x] = b[row * uniforms.N + col];
      } else {
        tile_b[local_id.y][local_id.x] = ${S.type.value}(0);
      }
      `,C="value += tile_a[local_id.y][k] * tile_b[k][local_id.x];");let q=t.alpha===1?"":"value *= uniforms.alpha;";return`
  ${$.registerUniforms(z).declareVariables(...T)}
  var<workgroup> tile_a: array<array<${w.type.storage}, ${d}>, ${d}>;
  var<workgroup> tile_b: array<array<${S.type.storage}, ${d}>, ${d}>;
  ${$.mainStart([d,d,1])}
    let tile_col_start = (workgroup_index % uniforms.num_tile_n) * ${d};
    let tile_row_start = (workgroup_index / uniforms.num_tile_n) * ${d};
    let num_tiles = (uniforms.K - 1) / ${d} + 1;
    var k_start = 0u;
    var value = ${E.type.value}(0);
    for (var t: u32 = 0u; t < num_tiles; t++) {
      ${A}
      k_start = k_start + ${d};
      workgroupBarrier();

      for (var k: u32 = 0u; k < ${d}; k++) {
        ${C}
      }
      workgroupBarrier();
    }

    ${q}
    let m = tile_row_start + local_id.y;
    let n = tile_col_start + local_id.x;
    ${k!=null?`let cOffset = ${k.broadcastedIndicesToOffset("vec2(m, n)",E)}; value += ${E.type.value}(uniforms.beta) * ${k.getByOffset("cOffset")};`:""}
    if (m < uniforms.M && n < uniforms.N) {
      output[m * uniforms.N + n] = value;
    }
  }`};return f?{name:"GemmShared",shaderCache:{hint:`${t.cacheKey}`,inputDependencies:_},getRunData:()=>({outputs:[{dims:u,dataType:e[0].dataType}],dispatchGroup:{x:l*c},programUniforms:g}),getShaderSource:x}:{name:"Gemm",shaderCache:{hint:`${t.cacheKey}`,inputDependencies:_},getRunData:()=>({outputs:[{dims:u,dataType:e[0].dataType}],dispatchGroup:{x:Math.ceil(m/64)},programUniforms:g}),getShaderSource:b}},Ec=e=>{let t=e.transA,r=e.transB,a=e.alpha,n=e.beta;return{transA:t,transB:r,alpha:a,beta:n,cacheKey:`${e.transA};${e.transB};${e.alpha===1}`}},zc=(e,t)=>{Su(e.inputs),e.compute(Tu(e.inputs,t))}}),Xe,it,wt,$t,Iu,Eu,zu,Cu,Ou,Au,Bu,Ru,Cc,Oc,Jm=P(()=>{ee(),ae(),ve(),ne(),[Xe,it,wt,$t]=[0,1,2,3],Iu=e=>{if(e[0].dims.length!==4)throw new Error("only 4-D tensor is supported.");if(e[0].dims.length!==e[1].dims.length)throw new Error("input dimensions must be equal to grid dimensions");if(e[0].dims.length-2!==e[1].dims[e[1].dims.length-1])throw new Error(`last dimension of grid must be equal to ${e[0].dims.length-2}`);if(e[0].dims[0]!==e[1].dims[0])throw new Error("grid batch size must match input batch size")},Eu=`
  fn gs_get_cubic_coeffs(x: f32) -> vec4<f32> {
    let cubic_alpha = -0.75f;
    let x_abs = abs(x);
    var coeffs: vec4<f32>;
    coeffs[0] = (((cubic_alpha * (x_abs + 1) - 5 * cubic_alpha) * (x_abs + 1) + 8 * cubic_alpha) * (x_abs + 1) - 4 * cubic_alpha);
    coeffs[1] = (((cubic_alpha + 2) * x_abs - (cubic_alpha + 3)) * x_abs * x_abs + 1);
    coeffs[2] = (((cubic_alpha + 2) * (1 - x_abs) - (cubic_alpha + 3)) * (1 - x_abs) * (1 - x_abs) + 1);
    coeffs[3] = (((cubic_alpha * (2 - x_abs) - 5 * cubic_alpha) * (2 - x_abs) + 8 * cubic_alpha) * (2 - x_abs) - 4 * cubic_alpha);
    return coeffs;
  }
`,zu=e=>`
  fn gs_bicubic_interpolate(p: mat4x4<${e}>, x: f32, y: f32) -> ${e} {
    var v: vec4<f32>;
    var coeffs = gs_get_cubic_coeffs(x);
    for (var i = 0; i < 4; i++) {
      v[i] = coeffs[0] * p[i][0] + coeffs[1] * p[i][1] + coeffs[2] * p[i][2] + coeffs[3] * p[i][3];
    }
    coeffs = gs_get_cubic_coeffs(y);
    let pixel = ${e}(coeffs[0] * v[0] + coeffs[1] * v[1] + coeffs[2] * v[2] + coeffs[3] * v[3]);
    return pixel;
  }
`,Cu=e=>`
  fn gs_denormalize(n: f32, length: i32) -> f32 {
    ${e.alignCorners===0?`
    // alignCorners: false => [-1, 1] to [-0.5, length - 0.5]
    return ((n + 1.0) * f32(length) - 1.0) / 2.0;
    `:`
    // alignCorners: true => [-1, 1] to [0, length - 1]
    return (n + 1.0) / 2.0 * (f32(length - 1));
    `}
  }
`,Ou=e=>`
  ${e.paddingMode==="reflection"?`
      fn gs_reflect(x: i32, x_min: f32, x_max: f32) -> u32 {
        var dx = 0.0;
        var fx = f32(x);
        let range = x_max - x_min;
        if (fx < x_min) {
          dx = x_min - fx;
          let n = u32(dx / range);
          let r = dx - f32(n) * range;
          if (n % 2 == 0) {
            fx = x_min + r;
          } else {
            fx = x_max - r;
          }
        } else if (fx > x_max) {
          dx = fx - x_max;
          let n = u32(dx / range);
          let r = dx - f32(n) * range;
          if (n % 2 == 0) {
            fx = x_max - r;
          } else {
            fx = x_min + r;
          }
        }
        return u32(fx);
      }`:""}
`,Au=(e,t,r)=>`
  fn pixel_at_grid(r: i32, c: i32, H: i32, W: i32, batch: u32, channel: u32, border: vec4<f32>) -> ${t} {
     var pixel = ${t}(0);
     var indices = vec4<u32>(0);
     indices[${Xe}] = batch;
     indices[${it}] = channel;`+(()=>{switch(r.paddingMode){case"zeros":return`
          if (r >= 0 && r < H && c >=0 && c < W) {
            indices[${wt}] = u32(r);
            indices[${$t}] = u32(c);
          } else {
            return ${t}(0);
          }
        `;case"border":return`
          indices[${wt}] = u32(clamp(r, 0, H - 1));
          indices[${$t}] = u32(clamp(c, 0, W - 1));
        `;case"reflection":return`
          indices[${wt}] = gs_reflect(r, border[1], border[3]);
          indices[${$t}] = gs_reflect(c, border[0], border[2]);
        `;default:throw new Error(`padding mode ${r.paddingMode} is not supported`)}})()+`
    return ${e.getByIndices("indices")};
  }
`,Bu=(e,t,r)=>(()=>{switch(r.mode){case"nearest":return`
          let result = pixel_at_grid(i32(round(y)), i32(round(x)), H_in, W_in, indices[${Xe}], indices[${it}], border);
        `;case"bilinear":return`
          let x1 = i32(floor(x));
          let y1 = i32(floor(y));
          let x2 = x1 + 1;
          let y2 = y1 + 1;

          let p11 = pixel_at_grid(y1, x1, H_in, W_in, indices[${Xe}], indices[${it}], border);
          let p12 = pixel_at_grid(y1, x2, H_in, W_in, indices[${Xe}], indices[${it}], border);
          let p21 = pixel_at_grid(y2, x1, H_in, W_in, indices[${Xe}], indices[${it}], border);
          let p22 = pixel_at_grid(y2, x2, H_in, W_in, indices[${Xe}], indices[${it}], border);

          let dx2 = ${t}(f32(x2) - x);
          let dx1 = ${t}(x - f32(x1));
          let dy2 = ${t}(f32(y2) - y);
          let dy1 = ${t}(y - f32(y1));
          let result = dy2 * (dx2 * p11 + dx1 * p12) + dy1 * (dx2 * p21 + dx1 * p22);
        `;case"bicubic":return`
          let x0 = i32(floor(x)) - 1;
          let y0 = i32(floor(y)) - 1;
          var p: mat4x4<${t}>;
          for (var h = 0; h < 4; h++) {
            for (var w = 0; w < 4; w++) {
              p[h][w] = pixel_at_grid(h + y0, w + x0, H_in, W_in, indices[${Xe}], indices[${it}], border);
            }
          }

          let dx = x - f32(x0 + 1);
          let dy = y - f32(y0 + 1);
          let result = gs_bicubic_interpolate(p, dx, dy);
        `;default:throw new Error(`mode ${r.mode} is not supported`)}})()+`${e.setByOffset("global_idx","result")}`,Ru=(e,t)=>{let r=R("x",e[0].dataType,e[0].dims.length),a=[e[1].dims[0],e[1].dims[1],e[1].dims[2]],n=R("grid",e[1].dataType,a.length,2),i=[e[0].dims[0],e[0].dims[1],e[1].dims[1],e[1].dims[2]];t.format==="NHWC"&&(i=[e[0].dims[0],e[1].dims[1],e[1].dims[2],e[0].dims[3]],[Xe,it,wt,$t]=[0,3,1,2]);let s=H("output",e[0].dataType,i.length),u=r.type.value,d=O.size(i),l=[{type:12,data:d},...Q(e[0].dims,a,i)],c=f=>`
  ${f.registerUniform("output_size","u32").declareVariables(r,n,s)}
  ${Eu}
  ${zu(u)}
  ${Cu(t)}
  ${Ou(t)}
  ${Au(r,u,t)}

  ${f.mainStart()}
    ${f.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}
      let H_in = i32(uniforms.x_shape[${wt}]);
      let W_in = i32(uniforms.x_shape[${$t}]);

      ${t.alignCorners===0?`
      let x_min = -0.5;
      let x_max = f32(W_in) - 0.5;
      let y_min = -0.5;
      let y_max = f32(H_in) - 0.5;
      `:`
      let x_min = 0.0;
      let x_max = f32(W_in) - 1.0;
      let y_min = 0.0;
      let y_max = f32(H_in) - 1.0;
      `};
      let border = vec4<f32>(x_min, y_min, x_max, y_max);

      let indices = ${s.offsetToIndices("global_idx")};
      var grid_indices = vec3<u32>(indices[${Xe}], indices[${wt}], indices[${$t}]);
      let nxy = ${n.getByIndices("grid_indices")};
      var x = gs_denormalize(f32(nxy[0]), W_in);
      var y = gs_denormalize(f32(nxy[1]), H_in);

      ${Bu(s,u,t)}
  }`;return{name:"GridSample",shaderCache:{hint:`${t.cacheKey}`,inputDependencies:["type","type"]},getRunData:f=>{let m=O.size(i);return{outputs:[{dims:i,dataType:f[0].dataType}],dispatchGroup:{x:Math.ceil(m/64)},programUniforms:l}},getShaderSource:c}},Cc=(e,t)=>{Iu(e.inputs),e.compute(Ru(e.inputs,t))},Oc=e=>pe({alignCorners:e.align_corners,mode:e.mode,paddingMode:e.padding_mode,format:e.format})}),Oe,Nu,Ac,Gi,Mu,ar,Bc,Rc=P(()=>{ee(),ae(),ve(),qa(),La(),ne(),gt(),Oe=(e,t)=>e.length>t&&e[t].dims.length>0?e[t]:void 0,Nu=(e,t)=>{let r=e[0],a=Oe(e,1),n=Oe(e,2),i=Oe(e,3),s=Oe(e,4),u=Oe(e,5),d=Oe(e,6),l=Oe(e,7);if(r.dims.length!==3&&r.dims.length!==5)throw new Error("Input query is expected to have 3 or 5 dimensions");let c=r.dims[0],f=r.dims[1],m=r.dims.length===3?r.dims[2]:t.numHeads*r.dims[4],g=f,_=0,b=0,x=Math.floor(m/t.numHeads);if(d&&l&&O.size(d.dims)&&O.size(l.dims)){if(d.dims.length!==4)throw new Error('Input "past_key" is expected to have 4 dimensions');if(d.dims[0]!==c||d.dims[1]!==t.numHeads||d.dims[3]!==x)throw new Error('Input "past_key" shape (batch_size, num_heads, past_sequence_length, head_size)');if(l.dims[0]!==c||l.dims[1]!==t.numHeads||l.dims[3]!==x)throw new Error('Input "past_value" shape (batch_size, num_heads, past_sequence_length, head_size)');if(d.dims[2]!==l.dims[2])throw new Error('Input "past_key" and "past_value" shall have same dim 2 (past_sequence_length)');if(l.dims.length!==4)throw new Error('Input "past_value" is expected to have 4 dimensions');_=d.dims[2],b=d.dims[2]}else if(d&&O.size(d.dims)||l&&O.size(l.dims))throw new Error('Input "past_key" and "past_value" shall be both present or both absent');let $;if(a&&O.size(a.dims)>0){if(r.dims.length!==3)throw new Error('Input "query" is expected to have 3 dimensions when key is given');if(a.dims.length<3||a.dims.length>5)throw new Error('Input "key" is expected to have 3, 4, or 5 dimensions');if(r.dims[0]!==a.dims[0])throw new Error('Input "query" and "key" shall have same dim 0 (batch size)');if(a.dims.length===3){if(a.dims[2]!==r.dims[2])throw new Error('Input "query" and "key" shall have same dim 2 (hidden_size)');$=2,g=a.dims[1]}else if(a.dims.length===5){if(a.dims[2]!==t.numHeads||a.dims[3]!==2||a.dims[4]!==x)throw new Error('Expect "key" shape (batch_size, kv_sequence_length, num_heads, 2, head_size) for packed kv');if(n)throw new Error('Expect "value" be none when "key" has packed kv format.');$=5,g=a.dims[1]}else{if(a.dims[1]!==t.numHeads||a.dims[3]!==x)throw new Error('Expect "key" shape (batch_size, num_heads, kv_sequence_length, head_size) for past_key');$=0,g=a.dims[2]}}else{if(r.dims.length!==5)throw new Error('Input "query" is expected to have 5 dimensions when key is empty');if(r.dims[2]!==t.numHeads||r.dims[3]!==3)throw new Error('Expect "query" shape (batch_size, kv_sequence_length, num_heads, 3, head_size) for packed kv');$=3}if(i&&O.size(i.dims)>0){if(i.dims.length!==1)throw new Error('Input "bias" is expected to have 1 dimension');if(a&&a.dims.length===5&&a.dims[3]===2)throw new Error("bias is not allowed for packed kv.")}let w=_+g,S=0;if(s&&O.size(s.dims)>0){S=8;let z=s.dims;throw z.length===1?z[0]===c?S=1:z[0]===3*c+2&&(S=3):z.length===2&&z[0]===c&&z[1]===w&&(S=5),S===8?new Error('Input "key_padding_mask" shape shall be (batch_size) or (batch_size, total_sequence_length)'):new Error("Mask not supported")}let k=!1,T=m;if(n&&O.size(n.dims)>0){if(n.dims.length!==3&&n.dims.length!==4)throw new Error('Input "value" is expected to have 3 or 4 dimensions');if(r.dims[0]!==n.dims[0])throw new Error('Input "query" and "value" shall have same dim 0 (batch_size)');if(n.dims.length===3){if(g!==n.dims[1])throw new Error('Input "key" and "value" shall have the same dim 1 (kv_sequence_length)');T=n.dims[2]}else{if(g!==n.dims[2])throw new Error('Input "key" and "value" shall have the same dim 2 (kv_sequence_length)');T=n.dims[1]*n.dims[3],k=!0}}let E=!1;if(s&&O.size(s.dims)>0)throw new Error("Key padding mask is not supported");if(u&&O.size(u.dims)>0){if(u.dims.length!==4)throw new Error('Input "attention_bias" is expected to have 4 dimensions');if(u.dims[0]!==c||u.dims[1]!==t.numHeads||u.dims[2]!==f||u.dims[3]!==w)throw new Error('Expect "attention_bias" shape (batch_size, num_heads, sequence_length, total_sequence_length)')}return{batchSize:c,sequenceLength:f,pastSequenceLength:_,kvSequenceLength:g,totalSequenceLength:w,maxSequenceLength:b,inputHiddenSize:0,hiddenSize:m,vHiddenSize:T,headSize:x,vHeadSize:Math.floor(T/t.numHeads),numHeads:t.numHeads,isUnidirectional:!1,pastPresentShareBuffer:!1,maskFilterValue:t.maskFilterValue,maskType:S,scale:t.scale,broadcastResPosBias:E,passPastInKv:k,qkvFormat:$}},Ac=e=>pe({...e}),Gi=pe({perm:[0,2,1,3]}),Mu=(e,t,r,a,n,i,s)=>{let u=[a,n,i],d=O.size(u),l=[{type:12,data:d},{type:12,data:s},{type:12,data:i}],c=f=>{let m=H("qkv_with_bias",t.dataType,u),g=R("qkv",t.dataType,u),_=R("bias",r.dataType,u),b=[{name:"output_size",type:"u32"},{name:"bias_offset",type:"u32"},{name:"hidden_size",type:"u32"}];return`
  ${f.registerUniforms(b).declareVariables(g,_,m)}
  ${f.mainStart()}
    ${f.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}
    let bias_offset_idx = (global_idx % uniforms.hidden_size) + uniforms.bias_offset;

    qkv_with_bias[global_idx] = qkv[global_idx] + bias[bias_offset_idx];
  }`};return e.compute({name:"MultiHeadAttentionAddBias",shaderCache:{inputDependencies:["type","type"]},getRunData:()=>({outputs:[{dims:u,dataType:t.dataType,gpuDataType:0}],dispatchGroup:{x:Math.ceil(d/64)},programUniforms:l}),getShaderSource:c},{inputs:[t,r],outputs:[-1]})[0]},ar=(e,t,r,a,n,i,s,u)=>{let d=i;if(s&&O.size(s.dims)>0){if(a===1)throw new Error("AddBiasReshape is not implemented. Please export your model with packed QKV or KV");return d=Mu(e,i,s,t,a,r*n,u),d=d.reshape([t,a,r,n]),r===1||a===1?d:e.compute(Me(d,Gi.perm),{inputs:[d],outputs:[-1]})[0]}else return i.dims.length===3&&(d=i.reshape([t,a,r,n])),r===1||a===1?d:e.compute(Me(d,Gi.perm),{inputs:[d],outputs:[-1]})[0]},Bc=(e,t)=>{let r=Nu(e.inputs,t),a=e.inputs[0],n=Oe(e.inputs,1),i=Oe(e.inputs,2),s=Oe(e.inputs,3),u=Oe(e.inputs,4),d=Oe(e.inputs,5),l=Oe(e.inputs,6),c=Oe(e.inputs,7);if(a.dims.length===5)throw new Error("Packed QKV is not implemented");if((n==null?void 0:n.dims.length)===5)throw new Error("Packed KV is not implemented");let f=n&&i&&n.dims.length===4&&i.dims.length===4,m=ar(e,r.batchSize,r.numHeads,r.sequenceLength,r.headSize,a,s,0);if(f)return ur(e,m,n,i,u,void 0,l,c,d,r);if(!n||!i)throw new Error("key and value must be provided");let g=ar(e,r.batchSize,r.numHeads,r.kvSequenceLength,r.headSize,n,s,r.hiddenSize),_=ar(e,r.batchSize,r.numHeads,r.kvSequenceLength,r.vHeadSize,i,s,2*r.hiddenSize);ur(e,m,g,_,u,void 0,l,c,d,r)}}),Du,Pu,Uu,qu,Sa,Nc,Mc,Dc=P(()=>{ee(),ae(),ve(),ne(),Du=e=>{if(!e||e.length<1)throw new Error("too few inputs")},Pu=(e,t)=>{let r=[],a=t.numOutputs;return e[1].dims[0]>0&&(e[1].getBigInt64Array().forEach(n=>r.push(Number(n))),a=r.length),pe({numOutputs:a,axis:t.axis,splitSizes:r})},Uu=e=>`
fn calculateOutputIndex(index: u32) -> u32 {
    for (var i: u32 = 0u; i < ${e}u; i += 1u ) {
    if (index < ${j("uniforms.size_in_split_axis","i",e)}) {
        return i;
    }
    }
    return ${e}u;
}`,qu=e=>{let t=e.length,r=[];for(let a=0;a<t;++a){let n=e[a].setByIndices("indices","input[global_idx]");t===1?r.push(n):a===0?r.push(`if (output_number == ${a}u) { ${n} }`):a===t-1?r.push(`else { ${n} }`):r.push(`else if (output_number == ${a}) { ${n} }`)}return`
      fn writeBufferData(output_number: u32, indices: ${e[0].type.indices}, global_idx: u32) {
        ${r.join(`
`)}
      }`},Sa=(e,t)=>{let r=e[0].dims,a=O.size(r),n=e[0].dataType,i=O.normalizeAxis(t.axis,r.length),s=new Array(t.numOutputs),u=R("input",n,r.length),d=new Array(t.numOutputs),l=[],c=[],f=0,m=[{type:12,data:a}];for(let _=0;_<t.numOutputs;_++){f+=t.splitSizes[_],d[_]=f;let b=r.slice();b[i]=t.splitSizes[_],c.push(b),s[_]=H(`output${_}`,n,b.length),l.push({dims:c[_],dataType:e[0].dataType})}m.push({type:12,data:d},...Q(r,...c));let g=_=>`
  ${_.registerUniform("input_size","u32").registerUniform("size_in_split_axis","u32",d.length).declareVariables(u,...s)}
  ${Uu(d.length)}
  ${qu(s)}

  ${_.mainStart()}
    ${_.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.input_size")}

    var indices = ${u.offsetToIndices("global_idx")};
    var index = ${u.indicesGet("indices",i)};
    let output_number = calculateOutputIndex(index);
    if (output_number != 0) {
      index -= ${j("uniforms.size_in_split_axis","output_number - 1u",d.length)};
      ${u.indicesSet("indices",i,"index")};
    }
    writeBufferData(output_number, indices, global_idx);
  }`;return{name:"Split",shaderCache:{hint:t.cacheKey,inputDependencies:["rank"]},getShaderSource:g,getRunData:()=>({outputs:l,dispatchGroup:{x:Math.ceil(a/64)},programUniforms:m})}},Nc=(e,t)=>{Du(e.inputs);let r=e.inputs.length===1?t:Pu(e.inputs,t);e.compute(Sa(e.inputs,r),{inputs:[0]})},Mc=e=>{let t=e.axis,r=e.splitSizes,a=e.numOutputs<0?r.length:e.numOutputs;if(a!==r.length)throw new Error("numOutputs and splitSizes lengh must be equal");return pe({axis:t,numOutputs:a,splitSizes:r})}}),Wu,Wr,Pc,Uc=P(()=>{ee(),ae(),ve(),ne(),Wu=(e,t)=>{let[r,a,n,i]=e,{numHeads:s,rotaryEmbeddingDim:u}=t;if(r.dims.length!==3&&r.dims.length!==4)throw new Error(`Input 'x' is expected to have 3 or 4 dimensions, got ${r.dims.length}`);if(!O.areEqual(a.dims,[])&&!O.areEqual(a.dims,[1])&&a.dims.length!==2)throw new Error(`Input 'position_ids' is expected to have 0, 1, or 2 dimensions, got ${a.dims.length}`);if(n.dims.length!==2)throw new Error(`Input 'cos_cache' is expected to have 2 dimensions, got ${n.dims.length}`);if(i.dims.length!==2)throw new Error(`Input 'sin_cache' is expected to have 2 dimensions, got ${i.dims.length}`);if(!O.areEqual(n.dims,i.dims))throw new Error("Inputs 'cos_cache' and 'sin_cache' are expected to have the same shape");if(u>0&&s===0)throw new Error("num_heads must be provided if rotary_embedding_dim is specified");let d=r.dims[0],l=r.dims[r.dims.length-2],c=n.dims[0],f=O.sizeFromDimension(r.dims,1)/l,m=u===0?n.dims[1]*2:f/s;if(u>m)throw new Error("rotary_embedding_dim must be less than or equal to head_size");if(a.dims.length===2){if(d!==a.dims[0])throw new Error(`Input 'position_ids' dimension 0 should be of size batch_size, got ${a.dims[0]}`);if(l!==a.dims[1])throw new Error(`Input 'position_ids' dimension 1 should be of size sequence_length, got ${a.dims[1]}`)}if(m/2!==n.dims[1]&&u/2!==n.dims[1])throw new Error(`Input 'cos_cache' dimension 1 should be same as head_size / 2 or rotary_embedding_dim / 2, got ${n.dims[1]}`);if(l>c)throw new Error("Updating cos_cache and sin_cache in RotaryEmbedding is not currently supported")},Wr=(e,t)=>{let{interleaved:r,numHeads:a,rotaryEmbeddingDim:n,scale:i}=t,s=e[0].dims[0],u=O.sizeFromDimension(e[0].dims,1),d=e[0].dims[e[0].dims.length-2],l=u/d,c=e[2].dims[1],f=n===0?c*2:l/a,m=new Array(s,d,l/f,f-c),g=O.computeStrides(m),_=[{type:1,data:i},{type:12,data:m},{type:12,data:g},...e[0].dims.length===3?new Array({type:12,data:[u,l,f,1]}):[],...e[0].dims.length===4?new Array({type:12,data:[u,f,d*f,1]}):[],...Q(e[0].dims,e[1].dims,e[2].dims,e[3].dims,e[0].dims)],b=x=>{let $=R("input",e[0].dataType,e[0].dims.length),w=R("position_ids",e[1].dataType,e[1].dims.length),S=R("cos_cache",e[2].dataType,e[2].dims.length),k=R("sin_cache",e[3].dataType,e[3].dims.length),T=H("output",e[0].dataType,e[0].dims.length);return x.registerUniforms([{name:"scale",type:"f32"},{name:"global_shape",type:"u32",length:m.length},{name:"global_strides",type:"u32",length:g.length},{name:"input_output_strides",type:"u32",length:g.length}]),`
        ${x.declareVariables($,w,S,k,T)}

        ${x.mainStart(Ut)}
          let half_rotary_emb_dim = uniforms.${S.name}_shape[1];
          let bsnh = global_idx / uniforms.global_strides % uniforms.global_shape;
          let size = uniforms.global_shape[0] * uniforms.global_strides[0];
          ${x.guardAgainstOutOfBoundsWorkgroupSizes("size")}

          if (bsnh[3] < half_rotary_emb_dim) {
            let position_ids_idx =
                ${w.broadcastedIndicesToOffset("bsnh.xy",H("",w.type.tensor,2))};
            let position_id =
                u32(${w.getByOffset("position_ids_idx")}) + select(0, bsnh[1], position_ids_idx == 0);
            let i = dot(bsnh, uniforms.input_output_strides) + select(0, bsnh[3], ${r});
            let j = i + select(half_rotary_emb_dim, 1, ${r});
            let re = ${$.getByOffset("i")} * ${S.get("position_id","bsnh[3]")} -
                ${$.getByOffset("j")} * ${k.get("position_id","bsnh[3]")};
            ${T.setByOffset("i","re")}
            let im = ${$.getByOffset("i")} * ${k.get("position_id","bsnh[3]")} +
                ${$.getByOffset("j")} * ${S.get("position_id","bsnh[3]")};
            ${T.setByOffset("j","im")}
          } else {
            let k = dot(bsnh, uniforms.input_output_strides) + half_rotary_emb_dim;
            ${T.setByOffset("k",$.getByOffset("k"))}
          }
        }`};return{name:"RotaryEmbedding",shaderCache:{hint:pe({interleaved:r}).cacheKey,inputDependencies:["rank","rank","rank","rank"]},getShaderSource:b,getRunData:()=>({outputs:[{dims:e[0].dims,dataType:e[0].dataType}],dispatchGroup:{x:Math.ceil(O.size(m)/Ut)},programUniforms:_})}},Pc=(e,t)=>{Wu(e.inputs,t),e.compute(Wr(e.inputs,t))}}),Vu,Lu,Hi,Gu,qc,eg=P(()=>{ve(),ee(),La(),Rc(),Dc(),gt(),Uc(),ne(),Vu=(e,t)=>{if(t.doRotary&&e.length<=7)throw new Error("cos_cache and sin_cache inputs are required if do_rotary is specified");let r=e[0],a=e[1],n=e[2],i=e[3],s=e[4];if(t.doRotary!==0&&e.length<=7)throw new Error("cos_cast and sin_cache are expected if do_rotary attribute is non-zero");if(t.localWindowSize!==-1)throw new Error("Local attention is not supported");if(t.softcap!==0)throw new Error("Softcap is not supported");if(t.rotaryInterleaved!==0)throw new Error("Rotary interleaved is not supported");if(t.smoothSoftmax)throw new Error("Smooth softmax is not supported");if(r.dims.length!==3&&r.dims.length!==5)throw new Error("Input query is expected to have 3 or 5 dimensions");let u=!1,d=r.dims[0],l=r.dims[1],c=r.dims.length===3?u?r.dims[2]/3:r.dims[2]:t.numHeads*r.dims[4],f=l,m=0,g=!a||a.dims.length===0,_=Math.floor(g?c/(t.numHeads+2*t.kvNumHeads):c/t.numHeads);g&&(c=_*t.numHeads);let b=i&&i.dims.length!==0,x=s&&s.dims.length!==0;if(b&&i.dims.length===4&&i.dims[0]===d&&i.dims[1]!==t.kvNumHeads&&i.dims[2]===t.kvNumHeads&&i.dims[3]===_)throw new Error("BSNH pastKey/pastValue is not supported");if(b&&x){if(i.dims.length!==4)throw new Error('Input "past_key" is expected to have 4 dimensions');if(s.dims.length!==4)throw new Error('Input "past_value" is expected to have 4 dimensions');m=i.dims[2]}else if(b||x)throw new Error('Input "past_key" and "past_value" shall be both present or both absent');let $=1;if(a&&a.dims.length>0){if(r.dims.length!==3)throw new Error('Input "query" is expected to have 3 dimensions when key is given');if(a.dims.length<3||a.dims.length>5)throw new Error('Input "key" is expected to have 3, 4, or 5 dimensions');if(r.dims[0]!==a.dims[0])throw new Error('Input "query" and "key" shall have same dim 0 (batch size)');if(a.dims.length===3){if(r.dims[2]%a.dims[2]!==0)throw new Error('Dimension 2 of "query" should be a multiple of "key"');f=a.dims[1]}else if(a.dims.length===5){if(a.dims[2]!==t.numHeads||a.dims[3]!==2||a.dims[4]!==_)throw new Error('Expect "key" shape (batch_size, kv_sequence_length, num_heads, 2, head_size) for packed kv');if(n)throw new Error('Expect "value" be none when "key" has packed kv format.');f=a.dims[1]}else{if(a.dims[1]!==t.numHeads||a.dims[3]!==_)throw new Error('Expect "key" shape (batch_size, num_heads, kv_sequence_length, head_size) for past_key');f=a.dims[2]}}else{if(r.dims.length!==3&&r.dims.length!==5)throw new Error('Input "query" is expected to have 3 or 5 dimensions when key is empty');if(r.dims.length===5&&(r.dims[2]!==t.numHeads||r.dims[3]!==3))throw new Error('Expect "query" shape (batch_size, kv_sequence_length, num_heads, 3, head_size) for packed kv');$=3}let w=0,S=!1,k=t.kvNumHeads?_*t.kvNumHeads:c;if(n&&n.dims.length>0){if(n.dims.length!==3&&n.dims.length!==4)throw new Error('Input "value" is expected to have 3 or 4 dimensions');if(r.dims[0]!==n.dims[0])throw new Error('Input "query" and "value" shall have same dim 0 (batch_size)');if(n.dims.length===3){if(f!==n.dims[1])throw new Error('Input "key" and "value" shall have the same dim 1 (kv_sequence_length)');k=n.dims[2]}else{if(f!==n.dims[2])throw new Error('Input "past_key" and "past_value" shall have the same dim 2 (kv_sequence_length)');k=n.dims[1]*n.dims[3],S=!0}}let T=e.length>4?e[5]:void 0;if(T&&T.dims.length!==1&&T.dims[0]!==d)throw new Error('Input "seqlens" is expected to have 1 dimension and the same dim 0 as batch_size');return{batchSize:d,sequenceLength:l,pastSequenceLength:m,kvSequenceLength:f,totalSequenceLength:-1,maxSequenceLength:-1,inputHiddenSize:0,hiddenSize:c,vHiddenSize:k,headSize:_,vHeadSize:Math.floor(k/t.kvNumHeads),numHeads:t.numHeads,kvNumHeads:t.kvNumHeads,nReps:t.numHeads/t.kvNumHeads,pastPresentShareBuffer:!1,maskType:w,scale:t.scale,broadcastResPosBias:!1,passPastInKv:S,qkvFormat:$}},Lu=pe({perm:[0,2,1,3]}),Hi=(e,t,r)=>{let a=t,n=r.kvNumHeads;return t.dims.length===3&&r.kvSequenceLength!==0&&(a=t.reshape([r.batchSize,r.kvSequenceLength,n,r.headSize]),a=e.compute(Me(a,Lu.perm),{inputs:[a],outputs:[-1]})[0]),a},Gu=(e,t,r,a)=>{let n=7,i=["type","type"],s=[e*t],u=e*t,d=[{type:12,data:u},{type:12,data:t},{type:12,data:e}],l=c=>{let f=R("seq_lens",r.dataType,r.dims),m=R("total_seq_lens",a.dataType,a.dims),g=H("pos_ids",n,s),_=[{name:"output_size",type:"u32"},{name:"sequence_length",type:"u32"},{name:"batch_size",type:"u32"}];return`
  ${c.registerUniforms(_).declareVariables(f,m,g)}
  ${c.mainStart()}
    ${c.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}
    let total_sequence_length = u32(${m.getByOffset("0")});
    let is_subsequent_prompt = uniforms.sequence_length > 1 && uniforms.sequence_length != total_sequence_length;
    let is_first_prompt = !is_subsequent_prompt && uniforms.sequence_length == total_sequence_length;
    let batch_idx = global_idx / uniforms.sequence_length;
    let sequence_idx = i32(global_idx % uniforms.sequence_length);
    var pos_id: i32 = 0;
    let seqlen = ${f.getByOffset("batch_idx")};
    let total_seqlen = seqlen + 1;
    if (is_first_prompt) {
      if (sequence_idx < total_seqlen) {
        pos_id = sequence_idx;
      } else {
        pos_id = 1;
      }
      ${g.setByOffset("global_idx","pos_id")}
    } else if (is_subsequent_prompt) {
      let past_seqlen = total_seqlen - i32(uniforms.sequence_length);
      if (past_seqlen + sequence_idx < total_seqlen) {
        pos_id = past_seqlen + sequence_idx;
      } else {
        pos_id = 1;
      }
      ${g.setByOffset("global_idx","pos_id")}
    } else if (global_idx < uniforms.batch_size) {
      ${g.setByOffset("global_idx","seqlen")}
    };
  }
  `};return{name:"GeneratePositionIds",shaderCache:{hint:`${e};${t}`,inputDependencies:i},getRunData:()=>({outputs:[{dims:s,dataType:n}],dispatchGroup:{x:Math.ceil(u/64)},programUniforms:d}),getShaderSource:l}},qc=(e,t)=>{var k;let r=Vu(e.inputs,t);if(e.inputs[0].dims.length===5)throw new Error("Packed QKV is not implemented");if(((k=e.inputs[1])==null?void 0:k.dims.length)===5)throw new Error("Packed KV is not implemented");let a=e.inputs[0],n=e.inputs[1]&&e.inputs[1].dims.length>0?e.inputs[1]:void 0,i=e.inputs[2]&&e.inputs[2].dims.length>0?e.inputs[2]:void 0,s=e.inputs[3]&&e.inputs[3].dims.length!==0?e.inputs[3]:void 0,u=e.inputs[4]&&e.inputs[4].dims.length!==0?e.inputs[4]:void 0,d=e.inputs.length>4?e.inputs[5]:void 0,l=e.inputs.length>5?e.inputs[6]:void 0,c=r.kvNumHeads?r.kvNumHeads:r.numHeads,f=pe({axis:2,numOutputs:3,splitSizes:[r.numHeads*r.headSize,c*r.headSize,c*r.headSize]}),[m,g,_]=!n&&!i?e.compute(Sa([a],f),{inputs:[a],outputs:[-1,-1,-1]}):[a,n,i],b,x;if(t.doRotary){let T=e.compute(Gu(r.batchSize,r.sequenceLength,d,l),{inputs:[d,l],outputs:[-1]})[0],E=e.inputs[7],z=e.inputs[8],C=pe({interleaved:t.rotaryInterleaved!==0,numHeads:r.numHeads,rotaryEmbeddingDim:0,scale:t.scale}),A=[m,T,E,z],q=[-1];b=e.compute(Wr(A,C),{inputs:A,outputs:q})[0],A.splice(0,1,g);let X=pe({interleaved:t.rotaryInterleaved!==0,numHeads:r.kvNumHeads,rotaryEmbeddingDim:0,scale:t.scale});x=e.compute(Wr(A,X),{inputs:A,outputs:q})[0]}let $=ar(e,r.batchSize,r.numHeads,r.sequenceLength,r.headSize,t.doRotary?b:m,void 0,0),w=Hi(e,t.doRotary?x:g,r),S=Hi(e,_,r);ur(e,$,w,S,void 0,void 0,s,u,void 0,r,d,l)}}),Fi,Hu,Fu,Wc,tg=P(()=>{ee(),ae(),gt(),ne(),Fi=(e,t,r,a,n,i,s,u)=>{let d=$e(i),l=d===1?"f32":`vec${d}f`,c=d===1?"vec2f":`mat2x${d}f`,f=n*s,m=64;f===1&&(m=256);let g=[n,s,i/d],_=[n,s,2],b=["rank","type","type"],x=[];x.push(...Q(g,_));let $=w=>{let S=R("x",t.dataType,3,d),k=R("scale",r.dataType,r.dims),T=R("bias",a.dataType,a.dims),E=H("output",1,3,2),z=[S,k,T,E];return`
  var<workgroup> workgroup_shared : array<${c}, ${m}>;
  const workgroup_size = ${m}u;
  ${w.declareVariables(...z)}
  ${w.mainStart(m)}
    let batch = workgroup_index / uniforms.x_shape[1];
    let channel = workgroup_index % uniforms.x_shape[1];
    let hight = uniforms.x_shape[2];
    // initialize workgroup memory
    var sum = ${l}(0);
    var squared_sum = ${l}(0);
    for (var h = local_idx; h < hight; h += workgroup_size) {
      let value = ${l}(${S.get("batch","channel","h")});
      sum += value;
      squared_sum += value * value;
    }
    workgroup_shared[local_idx] = ${c}(sum, squared_sum);
    workgroupBarrier();

    for (var currSize = workgroup_size >> 1;  currSize > 0; currSize = currSize >> 1) {
      if (local_idx < currSize) {
        workgroup_shared[local_idx] = workgroup_shared[local_idx] + workgroup_shared[local_idx + currSize];
      }
      workgroupBarrier();
    }
    if (local_idx == 0) {
      let sum_final = ${mt("workgroup_shared[0][0]",d)} / f32(hight * ${d});
      let squared_sum_final = ${mt("workgroup_shared[0][1]",d)} / f32(hight * ${d});

      let inv_std_dev = inverseSqrt(squared_sum_final - sum_final * sum_final + f32(${u}));
      let channel_scale = inv_std_dev * f32(scale[channel]);
      let channel_shift = f32(bias[channel]) - sum_final * channel_scale;
      output[workgroup_index] = vec2f(channel_scale, channel_shift);
    }
  }`};return e.compute({name:"InstanceNormComputeChannelScaleShift",shaderCache:{hint:`${d};${u};${m}`,inputDependencies:b},getRunData:()=>({outputs:[{dims:_,dataType:1}],dispatchGroup:{x:f},programUniforms:x}),getShaderSource:$},{inputs:[t,r,a],outputs:[-1]})[0]},Hu=(e,t,r)=>{let a=t[0].dims,n=a,i=2,s=a[0],u=a[1],d=O.sizeFromDimension(a,i),l=$e(d),c=O.size(n)/l,f=Fi(e,t[0],t[1],t[2],s,d,u,r.epsilon),m=[s,u,d/l],g=[s,u],_=["type","none"],b=x=>{let $=R("x",t[0].dataType,m.length,l),w=R("scale_shift",1,g.length,2),S=H("output",t[0].dataType,m.length,l),k=[$,w,S];return`
  ${x.registerUniform("output_size","u32").declareVariables(...k)}
  ${x.mainStart()}
  ${x.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}
      let outputIndices = ${S.offsetToIndices("global_idx")};
      let batch = outputIndices[0];
      let channel = outputIndices[1];
      let scale_shift = ${w.getByIndices("vec2<u32>(batch, channel)")};
      let value = ${$.getByOffset("global_idx")} * ${S.type.value}(scale_shift.x) + ${S.type.value}(scale_shift.y);
      ${S.setByOffset("global_idx","value")};
  }`};e.compute({name:"InstanceNormalization",shaderCache:{hint:`${l}`,inputDependencies:_},getRunData:()=>({outputs:[{dims:n,dataType:t[0].dataType}],dispatchGroup:{x:Math.ceil(c/64)},programUniforms:[{type:12,data:c},...Q(m,g,m)]}),getShaderSource:b},{inputs:[t[0],f]})},Fu=(e,t,r)=>{let a=t[0].dims,n=a,i=a[0],s=a[a.length-1],u=O.sizeFromDimension(a,1)/s,d=$e(s),l=O.size(n)/d,c=[{type:12,data:u},{type:12,data:Math.floor(s/d)}],f=["type","type"],m=!1,g=[0,a.length-1];for(let $=0;$<a.length-2;$++)m=m||a[$+1]!==1,g.push($+1);m=m&&a[a.length-1]!==1;let _=m?e.compute(Me(e.inputs[0],g),{inputs:[e.inputs[0]],outputs:[-1]})[0]:e.inputs[0].reshape(Array.from({length:a.length},($,w)=>a[g[w]])),b=Fi(e,_,t[1],t[2],i,u,s,r.epsilon),x=$=>{let w=ke(t[0].dataType),S=d===1?"vec2f":`mat${d}x2f`,k=z=>{let C=z===0?"x":"y",A=d===1?"f32":`vec${d}f`;switch(d){case 1:return`${w}(${A}(scale.${C}))`;case 2:return`vec2<${w}>(${A}(scale[0].${C}, scale[1].${C}))`;case 4:return`vec4<${w}>(${A}(scale[0].${C}, scale[1].${C}, scale[2].${C}, scale[3].${C}))`;default:throw new Error(`Not supported compoents ${d}`)}},T=R("input",t[0].dataType,t[0].dims,d),E=H("output",t[0].dataType,n,d);return`
  @group(0) @binding(0) var<storage, read> input : array<${T.type.storage}>;
  @group(0) @binding(1) var<storage, read> scale_input : array<${S}>;
  @group(0) @binding(2) var<storage, read_write> output : array<${E.type.storage}>;
  struct Uniforms {H: u32, C : u32};
  @group(0) @binding(3) var<uniform> uniforms: Uniforms;

  ${$.mainStart()}
    let current_image_number = global_idx / (uniforms.C * uniforms.H);
    let current_channel_number = global_idx % uniforms.C;

    let scale_offset = current_image_number * uniforms.C + current_channel_number;
    let scale = scale_input[scale_offset];
    output[global_idx] = fma(input[global_idx], ${k(0)}, ${k(1)});
  }`};e.compute({name:"InstanceNormalizationNHWC",shaderCache:{hint:`${d}`,inputDependencies:f},getRunData:()=>({outputs:[{dims:n,dataType:t[0].dataType}],dispatchGroup:{x:Math.ceil(l/64)},programUniforms:c}),getShaderSource:x},{inputs:[t[0],b]})},Wc=(e,t)=>{t.format==="NHWC"?Fu(e,e.inputs,t):Hu(e,e.inputs,t)}}),ju,Ku,Vc,rg=P(()=>{ee(),ae(),ne(),ju=e=>{if(!e||e.length<2)throw new Error("layerNorm requires at least 2 inputs.")},Ku=(e,t,r)=>{let a=t.simplified,n=e[0].dims,i=e[1],s=!a&&e[2],u=n,d=O.normalizeAxis(t.axis,n.length),l=O.sizeToDimension(n,d),c=O.sizeFromDimension(n,d),f=O.size(i.dims),m=s?O.size(s.dims):0;if(f!==c||s&&m!==c)throw new Error(`Size of X.shape()[axis:] == ${c}.
       Size of scale and bias (if provided) must match this.
       Got scale size of ${f} and bias size of ${m}`);let g=[];for(let T=0;T<n.length;++T)T<d?g.push(n[T]):g.push(1);let _=$e(c),b=["type","type"],x=[{type:12,data:l},{type:1,data:c},{type:12,data:Math.floor(c/_)},{type:1,data:t.epsilon}];s&&b.push("type");let $=r>1,w=r>2,S=T=>{let E=ke(e[0].dataType),z=[R("x",e[0].dataType,e[0].dims,_),R("scale",i.dataType,i.dims,_)];s&&z.push(R("bias",s.dataType,s.dims,_)),z.push(H("output",e[0].dataType,u,_)),$&&z.push(H("mean_data_output",1,g)),w&&z.push(H("inv_std_output",1,g));let C=[{name:"norm_count",type:"u32"},{name:"norm_size",type:"f32"},{name:"norm_size_vectorized",type:"u32"},{name:"epsilon",type:"f32"}];return`
  ${T.registerUniforms(C).declareVariables(...z)}
  ${T.mainStart()}
    ${T.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.norm_count")}
    let offset = global_idx * uniforms.norm_size_vectorized;
    var mean_vector = ${ga("f32",_)};
    var mean_square_vector = ${ga("f32",_)};

    for (var h: u32 = 0u; h < uniforms.norm_size_vectorized; h++) {
      let value = ${Dt(E,_,"x[h + offset]")};
      mean_vector += value;
      mean_square_vector += value * value;
    }
    let mean = ${mt("mean_vector",_)} / uniforms.norm_size;
    let inv_std_dev = inverseSqrt(${mt("mean_square_vector",_)} / uniforms.norm_size ${a?"":"- mean * mean"} + uniforms.epsilon);

    for (var j: u32 = 0; j < uniforms.norm_size_vectorized; j++) {
      let f32input = ${Dt(E,_,"x[j + offset]")};
      let f32scale = ${Dt(E,_,"scale[j]")};
      output[j + offset] = ${z[0].type.value}((f32input ${a?"":"- mean"}) * inv_std_dev * f32scale
        ${s?`+ ${Dt(E,_,"bias[j]")}`:""}
      );
    }

    ${$?"mean_data_output[global_idx] = mean":""};
    ${w?"inv_std_output[global_idx] = inv_std_dev":""};
  }`},k=[{dims:u,dataType:e[0].dataType}];return $&&k.push({dims:g,dataType:1}),w&&k.push({dims:g,dataType:1}),{name:"LayerNormalization",shaderCache:{hint:`${_};${r};${a}`,inputDependencies:b},getRunData:()=>({outputs:k,dispatchGroup:{x:Math.ceil(l/64)},programUniforms:x}),getShaderSource:S}},Vc=(e,t)=>{ju(e.inputs),e.compute(Ku(e.inputs,t,e.outputCount))}}),Zu,Lc,ig=P(()=>{ae(),Ka(),Za(),Zu=e=>{if(!e||e.length!==2)throw new Error("MatMul requires 2 inputs.");if(e[0].dims[e[0].dims.length-1]!==e[1].dims[e[1].dims.length-2])throw new Error("shared dimension does not match.")},Lc=e=>{Zu(e.inputs);let t=Pt.calcShape(e.inputs[0].dims,e.inputs[1].dims,!0);if(!t)throw new Error("Can't use matmul on the given tensors");let r=t[t.length-1],a=e.inputs[0].dims[e.inputs[0].dims.length-1];if(r<8&&a<8)e.compute(ja(e.inputs,{activation:""},t));else{let n=t[t.length-2],i=O.size(e.inputs[0].dims.slice(0,-2)),s=O.size(e.inputs[1].dims.slice(0,-2));if(i!==1&&n===1&&s===1){let u=e.inputs[0].reshape([1,i,a]),d=e.inputs[1].reshape([1,a,r]),l=[1,i,r],c=[u,d];e.compute(qr(c,{activation:""},t,l),{inputs:c})}else e.compute(qr(e.inputs,{activation:""},t))}}}),Qu,Xu,Yu,Gc,Hc,ag=P(()=>{ee(),ae(),ve(),ne(),Qu=(e,t)=>{if(e.length<3||e.length>4)throw new Error("MatMulNBits requires 3 or 4 inputs");let r=e[0],a=r.dims.length;if(r.dims[a-1]!==t.k)throw new Error("The last dim of input shape does not match the k value");let n=Math.floor((t.k+t.blockSize-1)/t.blockSize),i=t.blockSize/8*t.bits,s=e[1];if(!O.areEqual(s.dims,[t.n,n,i]))throw new Error("The second inputs must be 3D tensor with shape N X nBlocksPerCol X blobSize");let u=e[2].dims;if(O.size(u)!==t.n*n)throw new Error("scales input size error.");if(e.length===4){let d=e[3].dims,l=t.bits>4?t.n*n:t.n*Math.floor((n+1)/2);if(O.size(d)!==l)throw new Error("zeroPoints input size error.")}},Xu=(e,t)=>{let r=e[0].dims,a=r.length,n=r[a-2],i=t.k,s=t.n,u=r.slice(0,a-2),d=O.size(u),l=e[1].dims[2]/4,c=e[0].dataType,f=$e(t.k),m=$e(l),g=$e(s),_=u.concat([n,s]),b=n>1&&s/g%2===0?2:1,x=O.size(_)/g/b,$=64,w=[],S=[d,n,i/f],k=O.convertShape(e[1].dims).slice();k.splice(-1,1,l/m),w.push(...Q(S)),w.push(...Q(k)),w.push(...Q(e[2].dims)),e.length===4&&w.push(...Q(O.convertShape(e[3].dims)));let T=[d,n,s/g];w.push(...Q(T));let E=z=>{let C=S.length,A=R("a",e[0].dataType,C,f),q=R("b",12,k.length,m),X=R("scales",e[2].dataType,e[2].dims.length),G=[A,q,X],Z=e.length===4?R("zero_points",12,e[3].dims.length):void 0;Z&&G.push(Z);let oe=T.length,re=H("output",e[0].dataType,oe,g),L=ke(e[0].dataType),ie=(()=>{switch(f){case 1:return`array<${L}, 8>`;case 2:return`mat4x2<${L}>`;case 4:return`mat2x4<${L}>`;default:throw new Error(`${f}-component is not supported.`)}})(),F=()=>{let N=`
          // reuse a data
            var input_offset = ${A.indicesToOffset(`${A.type.indices}(batch, row, word_offset)`)};
            var a_data: ${ie};
            for (var j: u32 = 0; j < ${8/f}; j++) {
              a_data[j] = ${A.getByOffset("input_offset")};
              input_offset++;
            }
          `;for(let U=0;U<g*b;U++)N+=`
            b_value = ${m===1?`b${U}_data`:`b${U}_data[i]`};
            b_value_lower = unpack4xU8(b_value & b_mask);
            b_value_upper = unpack4xU8((b_value >> 4) & b_mask);
            b_quantized_values = ${ie}(${Array.from({length:4},(V,te)=>`${L}(b_value_lower[${te}]), ${L}(b_value_upper[${te}])`).join(", ")});
            b_dequantized_values = ${f===1?`${ie}(${Array.from({length:8},(V,te)=>`(b_quantized_values[${te}] - ${Z?`zero_point${U}`:"zero_point"}) * scale${U}`).join(", ")});`:`(b_quantized_values - ${ie}(${Array(8).fill(`${Z?`zero_point${U}`:"zero_point"}`).join(",")})) * scale${U};`};
            workgroup_shared[local_id.x * ${b} + ${Math.floor(U/g)}]${g>1?`[${U%g}]`:""} += ${Array.from({length:8/f},(V,te)=>`${f===1?`a_data[${te}] * b_dequantized_values[${te}]`:`dot(a_data[${te}], b_dequantized_values[${te}])`}`).join(" + ")};
          `;return N},Y=()=>{let N=`
            var col_index = col * ${g};
            ${Z?`
            let zero_point_bytes_per_col = (nBlocksPerCol + 1) / 2;
            var zero_point_byte_count: u32;
            var zero_point_word_index: u32;
            var zero_point_byte_offset: u32;
            let zero_point_nibble_offset: u32 = block & 0x1u;
            var zero_point_bits_offset: u32;
            var zero_point_word: u32;`:`
            // The default zero point is 8 for unsigned 4-bit quantization.
            let zero_point = ${L}(8);`}
            `;for(let U=0;U<g*b;U++)N+=`
            let scale${U} = ${X.getByOffset("col_index * nBlocksPerCol + block")};
            ${Z?`
            zero_point_byte_count = col_index * zero_point_bytes_per_col + (block >> 0x1u);
            zero_point_word_index = zero_point_byte_count >> 0x2u;
            zero_point_byte_offset = zero_point_byte_count & 0x3u;
            zero_point_bits_offset = (zero_point_byte_offset << 3) + (zero_point_nibble_offset << 2);
            zero_point_word = ${Z.getByOffset("zero_point_word_index")} >> zero_point_bits_offset;
            let zero_point${U} = ${L}((zero_point_word) & 0xFu);`:""}
            col_index += 1;`;return N},ye=()=>{let N=`col_index = col * ${g};`;for(let U=0;U<g*b;U++)N+=`
            let b${U}_data = ${q.getByIndices(`${q.type.indices}(col_index, block, word)`)};
            col_index += 1;`;return N+=`
            var b_value: u32;
            let b_mask: u32 = 0x0F0F0F0Fu;
            var b_value_lower: vec4<u32>;
            var b_value_upper: vec4<u32>;
            var b_quantized_values: ${ie};
            var b_dequantized_values: ${ie};`,N};return`
        var<workgroup> workgroup_shared: array<${re.type.value}, ${b*$}>;
        ${z.declareVariables(...G,re)}
        ${z.mainStart([$,1,1])}
          let output_indices = ${re.offsetToIndices(`(global_idx / ${$}) * ${b}`)};
          let col = output_indices[2];
          let row = output_indices[1];
          let batch = output_indices[0];
          let nBlocksPerCol = uniforms.b_shape[1];

          for (var block = local_id.x; block < nBlocksPerCol; block += ${$}) {
            //process one block
            var word_offset: u32 = block * ${t.blockSize/f};
            ${Y()}
            for (var word: u32 = 0; word < ${l}; word += ${m}) {
              ${ye()}
              for (var i: u32 = 0; i < ${m}; i++) {
                ${F()}
                word_offset += ${8/f};
              }
            }
          }
          workgroupBarrier();

          if (local_id.x < ${b}) {
            var output_value: ${re.type.value} = ${re.type.value}(0);
            var workgroup_shared_offset: u32 = local_id.x;
            for (var b: u32 = 0u; b < ${$}u; b++) {
              output_value += workgroup_shared[workgroup_shared_offset];
              workgroup_shared_offset += ${b};
            }
            ${re.setByIndices(`${re.type.indices}(batch, row, col + local_id.x)`,"output_value")};
          }
        }`};return{name:"MatMulNBits",shaderCache:{hint:`${t.blockSize};${t.bits};${f};${m};${g};${b};${$}`,inputDependencies:Array(e.length).fill("rank")},getRunData:()=>({outputs:[{dims:_,dataType:c}],dispatchGroup:{x},programUniforms:w}),getShaderSource:E}},Yu=(e,t)=>{let r=e[0].dims,a=r.length,n=r[a-2],i=t.k,s=t.n,u=r.slice(0,a-2),d=O.size(u),l=e[1].dims[2]/4,c=e[0].dataType,f=$e(t.k),m=$e(l),g=u.concat([n,s]),_=128,b=s%8===0?8:s%4===0?4:1,x=_/b,$=x*m*8,w=$/f,S=$/t.blockSize,k=O.size(g)/b,T=[],E=[d,n,i/f],z=O.convertShape(e[1].dims).slice();z.splice(-1,1,l/m),T.push(...Q(E)),T.push(...Q(z)),T.push(...Q(e[2].dims)),e.length===4&&T.push(...Q(O.convertShape(e[3].dims)));let C=[d,n,s];T.push(...Q(C));let A=q=>{let X=E.length,G=R("a",e[0].dataType,X,f),Z=R("b",12,z.length,m),oe=R("scales",e[2].dataType,e[2].dims.length),re=[G,Z,oe],L=e.length===4?R("zero_points",12,e[3].dims.length):void 0;L&&re.push(L);let ie=C.length,F=H("output",e[0].dataType,ie),Y=ke(e[0].dataType),ye=()=>{switch(f){case 1:return`
          let a_data0 = vec4<${Y}>(sub_a[word_offset], sub_a[word_offset + 1], sub_a[word_offset + 2], sub_a[word_offset + 3]);
          let a_data1 = vec4<${Y}>(sub_a[word_offset + 4], sub_a[word_offset + 5], sub_a[word_offset + 6], sub_a[word_offset + 7]);`;case 2:return`
          let a_data0 = vec4<${Y}>(sub_a[word_offset], sub_a[word_offset + 1]);
          let a_data1 = vec4<${Y}>(sub_a[word_offset + 2], sub_a[word_offset + 3]);`;case 4:return`
          let a_data0 = sub_a[word_offset];
          let a_data1 = sub_a[word_offset + 1];`;default:throw new Error(`${f}-component is not supported.`)}};return`
        var<workgroup> sub_a: array<${G.type.value}, ${w}>;
        var<workgroup> inter_results: array<array<${F.type.value}, ${x}>, ${b}>;
        ${q.declareVariables(...re,F)}
        ${q.mainStart([x,b,1])}
          let output_indices = ${F.offsetToIndices(`workgroup_index * ${b}`)};
          let col = output_indices[2];
          let row = output_indices[1];
          let batch = output_indices[0];
          let n_blocks_per_col = uniforms.b_shape[1];
          let num_tiles =  (n_blocks_per_col - 1) / ${S} + 1;

          // Loop over shared dimension.
          for (var tile: u32 = 0; tile < num_tiles; tile += 1) {
            let a_col_start = tile * ${w};
            // load one tile A data into shared memory.
            for (var a_offset = local_idx; a_offset < ${w}; a_offset += ${_})
            {
              let a_col = a_col_start + a_offset;
              if (a_col < uniforms.a_shape[2])
              {
                sub_a[a_offset] = ${G.getByIndices(`${G.type.indices}(batch, row, a_col)`)};
              } else {
                sub_a[a_offset] = ${G.type.value}(0);
              }
            }
            workgroupBarrier();

            // each thread process one block
            let b_row = col + local_id.y;
            let block = tile * ${S} + local_id.x;
            ${L?`
            let zero_point_bytes_per_col = (n_blocks_per_col + 1) / 2;
            let zero_point_byte_count = b_row * zero_point_bytes_per_col + (block >> 0x1u);
            let zero_point_word_index = zero_point_byte_count >> 0x2u;
            let zero_point_byte_offset = zero_point_byte_count & 0x3u;
            let zero_point_nibble_offset: u32 = block & 0x1u;
            let zero_point_bits_offset = (zero_point_byte_offset << 3) + (zero_point_nibble_offset << 2);
            let zero_point_word = ${L.getByOffset("zero_point_word_index")} >> zero_point_bits_offset;
            let zero_point = ${Y}((zero_point_word) & 0xFu);`:`
            // The default zero point is 8 for unsigned 4-bit quantization.
            let zero_point = ${Y}(8);`}
            let scale = ${oe.getByOffset("b_row * n_blocks_per_col + block")};
            let b_data = ${Z.getByIndices(`${Z.type.indices}(b_row, block, 0)`)};
            var word_offset = local_id.x * ${t.blockSize/f};
            for (var i: u32 = 0; i < ${m}; i++) {
              ${ye()}
              let b_value = ${m===1?"b_data":"b_data[i]"};
              let b_value_lower = unpack4xU8(b_value & 0x0F0F0F0Fu);
              let b_value_upper = unpack4xU8((b_value >> 4) & 0x0F0F0F0Fu);
              let b_quantized_values = mat2x4<${Y}>(${Array.from({length:4},(N,U)=>`${Y}(b_value_lower[${U}]), ${Y}(b_value_upper[${U}])`).join(", ")});
              let b_dequantized_values = (b_quantized_values - mat2x4<${Y}>(${Array(8).fill("zero_point").join(",")})) * scale;
              inter_results[local_id.y][local_id.x] += ${Array.from({length:2},(N,U)=>`${`dot(a_data${U}, b_dequantized_values[${U}])`}`).join(" + ")};
              word_offset += ${8/f};
            }
            workgroupBarrier();
          }

          if (local_idx < ${b}) {
            var output_value: ${F.type.value} = ${F.type.value}(0);
            for (var b = 0u; b < ${x}; b++) {
              output_value += inter_results[local_idx][b];
            }
            if (col + local_idx < uniforms.output_shape[2])
            {
              ${F.setByIndices(`${F.type.indices}(batch, row, col + local_idx)`,"output_value")}
            }
          }
        }`};return{name:"BlockwiseMatMulNBits32",shaderCache:{hint:`${t.blockSize};${f};${m};${x};${b}`,inputDependencies:Array(e.length).fill("rank")},getRunData:()=>({outputs:[{dims:g,dataType:c}],dispatchGroup:{x:k},programUniforms:T}),getShaderSource:A}},Gc=(e,t)=>{Qu(e.inputs,t),t.blockSize===32&&e.adapterInfo.isVendor("intel")&&e.adapterInfo.isArchitecture("gen-12lp")?e.compute(Yu(e.inputs,t)):e.compute(Xu(e.inputs,t))},Hc=e=>pe(e)}),Ju,el,tl,rl,il,al,nl,sl,Fc,ng=P(()=>{ee(),ae(),ne(),Ju=e=>{if(!e||e.length<1)throw new Error("Too few inputs");if(e[0].dataType!==1&&e[0].dataType!==10)throw new Error("Input type must be float or float16.");if(e.length>=2){let t=e[0].dims.length*2===e[1].dims[0];if(e.length===4&&(t=e[3].dims[0]*2===e[1].dims[0]),!t)throw new Error("The pads should be a 1D tensor of shape [2 * input_rank] or [2 * num_axes].")}},el=(e,t,r)=>{let a="";for(let n=t-1;n>=0;--n)a+=`
            k = i32(${e.indicesGet("indices",n)}) - ${j("uniforms.pads",n,r)};
            if (k < 0) {
              break;
            }
            if (k >= i32(${j("uniforms.x_shape",n,t)})) {
              break;
            }
            offset += k * i32(${j("uniforms.x_strides",n,t)});
        `;return`
          value = ${e.type.value}(uniforms.constant_value);
          for (var i = 0; i < 1; i++) {
            var offset = 0;
            var k = 0;
            ${a}
            value = x[offset];
          }
      `},tl=(e,t,r)=>{let a="";for(let n=t-1;n>=0;--n)a+=`
                k = i32(${e.indicesGet("indices",n)}) - ${j("uniforms.pads",n,r)};
                if (k < 0) {
                  k = -k;
                }
                {
                  let _2n_1 = 2 * (i32(${j("uniforms.x_shape",n,t)}) - 1);
                  k = k % _2n_1;
                  if(k >= i32(${j("uniforms.x_shape",n,t)})) {
                    k = _2n_1 - k;
                  }
                }
                offset += k * i32(${j("uniforms.x_strides",n,t)});
            `;return`
              var offset = 0;
              var k = 0;
              ${a}
              value = x[offset];
          `},rl=(e,t,r)=>{let a="";for(let n=t-1;n>=0;--n)a+=`
                k = i32(${e.indicesGet("indices",n)}) - ${j("uniforms.pads",n,r)};
                if (k < 0) {
                  k = 0;
                }
                if (k >= i32(${j("uniforms.x_shape",n,t)})) {
                  k = i32(${j("uniforms.x_shape",n,t)}) - 1;
                }
                offset += k * i32(${j("uniforms.x_strides",n,t)});
            `;return`
              var offset = 0;
              var k = 0;
              ${a}
              value = x[offset];
          `},il=(e,t,r)=>{let a="";for(let n=t-1;n>=0;--n)a+=`
                k = i32(${e.indicesGet("indices",n)}) - ${j("uniforms.pads",n,r)};
                if (k < 0)  {
                  k += i32(${j("uniforms.x_shape",n,t)}]);
                }
                if (k >= i32(${j("uniforms.x_shape",n,t)})) {
                  k -= i32(${j("uniforms.x_shape",n,t)});
                }
                offset += k * i32(${j("uniforms.x_strides",n,t)});
            `;return`
              var offset = 0;
              var k = 0;
              ${a}
              value = x[offset];
          `},al=(e,t,r)=>{switch(r.mode){case 0:return el(e,t,r.pads.length);case 1:return tl(e,t,r.pads.length);case 2:return rl(e,t,r.pads.length);case 3:return il(e,t,r.pads.length);default:throw new Error("Invalid mode")}},nl=(e,t)=>{let r=O.padShape(e[0].dims.slice(),t.pads),a=e[0].dims,n=O.size(r),i=[{type:12,data:n},{type:6,data:t.pads}],s=e.length>=3&&e[2].data;t.mode===0&&i.push({type:s?e[2].dataType:1,data:t.value}),i.push(...Q(e[0].dims,r));let u=["rank"],d=l=>{let c=H("output",e[0].dataType,r.length),f=R("x",e[0].dataType,a.length),m=f.type.value,g=al(c,a.length,t),_=[{name:"output_size",type:"u32"},{name:"pads",type:"i32",length:t.pads.length}];return t.mode===0&&_.push({name:"constant_value",type:s?m:"f32"}),`
            ${l.registerUniforms(_).declareVariables(f,c)}
            ${l.mainStart()}
            ${l.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}

            let indices = ${c.offsetToIndices("global_idx")};

            var value = ${m}(0);
            ${g}
            output[global_idx] = value;
        }`};return{name:"Pad",shaderCache:{hint:`${t.mode}${s}`,inputDependencies:u},getRunData:()=>({outputs:[{dims:r,dataType:e[0].dataType}],dispatchGroup:{x:Math.ceil(O.size(r)/64)},programUniforms:i}),getShaderSource:d}},sl=(e,t)=>{if(e.length>1){let r=e[1].getBigInt64Array(),a=e.length>=3&&e[2].data?e[2].dataType===10?e[2].getUint16Array()[0]:e[2].getFloat32Array()[0]:0,n=e[0].dims.length,i=new Int32Array(2*n).fill(0);if(e.length>=4){let u=e[3].getBigInt64Array();for(let d=0;d<u.length;d++)i[Number(u[d])]=Number(r[d]),i[Number(u[d])+n]=Number(r[d+u.length])}else r.forEach((u,d)=>i[Number(d)]=Number(u));let s=[];return i.forEach(u=>s.push(u)),{mode:t.mode,value:a,pads:s}}else return t},Fc=(e,t)=>{Ju(e.inputs);let r=sl(e.inputs,t);e.compute(nl(e.inputs,r),{inputs:[0]})}}),Xt,ji,Ki,Zi,Qi,ol,ul,Xi,Yi,jc,Kc,Ji,Zc,Qc,ea,Xc,Yc,Jc,ef,sg=P(()=>{je(),ee(),ae(),ne(),Xt=e=>{if(_e.webgpu.validateInputContent&&(!e||e.length!==1))throw new Error("Pool ops requires 1 input.")},ji=(e,t,r)=>{let a=t.format==="NHWC",n=e.dims.slice();a&&n.splice(1,0,n.pop());let i=Object.hasOwnProperty.call(t,"dilations"),s=t.kernelShape.slice(),u=t.strides.slice(),d=i?t.dilations.slice():[],l=t.pads.slice();Pr.adjustPoolAttributes(r,n,s,u,d,l);let c=Pr.computePoolOutputShape(r,n,u,d,s,l,t.autoPad),f=Object.assign({},t);i?Object.assign(f,{kernelShape:s,strides:u,pads:l,dilations:d,cacheKey:t.cacheKey}):Object.assign(f,{kernelShape:s,strides:u,pads:l,cacheKey:t.cacheKey});let m=c.slice();return m.push(m.splice(1,1)[0]),[f,a?m:c]},Ki=(e,t)=>{let r=t.format==="NHWC",a=O.size(e),n=O.size(t.kernelShape),i=[{type:12,data:a},{type:12,data:n}],s=[{name:"outputSize",type:"u32"},{name:"kernelSize",type:"u32"}];if(t.kernelShape.length<=2){let u=t.kernelShape[t.kernelShape.length-1],d=t.strides[t.strides.length-1],l=t.pads[t.pads.length/2-1],c=t.pads[t.pads.length-1],f=!!(l+c);i.push({type:12,data:u},{type:12,data:d},{type:12,data:l},{type:12,data:c}),s.push({name:"kw",type:"u32"},{name:"sw",type:"u32"},{name:"pwStart",type:"u32"},{name:"pwEnd",type:"u32"});let m=!1;if(t.kernelShape.length===2){let g=t.kernelShape[t.kernelShape.length-2],_=t.strides[t.strides.length-2],b=t.pads[t.pads.length/2-2],x=t.pads[t.pads.length-2];m=!!(b+x),i.push({type:12,data:g},{type:12,data:_},{type:12,data:b},{type:12,data:x}),s.push({name:"kh",type:"u32"},{name:"sh",type:"u32"},{name:"phStart",type:"u32"},{name:"phEnd",type:"u32"})}return[i,s,!0,f,m]}else{if(r)throw new Error("Pooling with kernelShape.length > 2 is not supported for NHWC format.");let u=O.computeStrides(t.kernelShape);i.push({type:12,data:u},{type:12,data:t.pads},{type:12,data:t.strides}),s.push({name:"kernelStrides",type:"u32",length:u.length},{name:"pads",type:"u32",length:t.pads.length},{name:"strides",type:"u32",length:t.strides.length});let d=t.pads.reduce((l,c)=>l+c);return[i,s,!!d,!1,!1]}},Zi=(e,t,r,a,n,i,s,u,d,l,c,f)=>{let m=n.format==="NHWC",g=t.type.value,_=H("output",t.type.tensor,a);if(n.kernelShape.length<=2){let b="",x="",$="",w=r-(m?2:1);if(c?b=`
                for (var i: u32 = 0u; i < uniforms.kw; i++) {
                  xIndices[${w}] = indices[${w}] * uniforms.sw - uniforms.pwStart + i;
                  if (xIndices[${w}] < 0 || xIndices[${w}]
                      >= uniforms.x_shape[${w}]) {
                    pad++;
                    continue;
                  }
                  let x_val = x[${t.indicesToOffset("xIndices")}];
                  ${i}
                }`:b=`
                for (var i: u32 = 0u; i < uniforms.kw; i++) {
                  xIndices[${w}] = indices[${w}] * uniforms.sw - uniforms.pwStart + i;
                  let x_val = x[${t.indicesToOffset("xIndices")}];
                  ${i}
                }`,n.kernelShape.length===2){let S=r-(m?3:2);f?x=`
                for (var j: u32 = 0u; j < uniforms.kh; j++) {
                  xIndices[${S}] = indices[${S}] * uniforms.sh - uniforms.phStart + j;
                  if (xIndices[${S}] < 0 || xIndices[${S}] >= uniforms.x_shape[${S}]) {
                    pad += i32(uniforms.kw);
                    continue;
                  }
              `:x=`
                for (var j: u32 = 0u; j < uniforms.kh; j++) {
                  xIndices[${S}] = indices[${S}] * uniforms.sh - uniforms.phStart + j;
                `,$=`
              }
            `}return`
            ${e.registerUniforms(d).declareVariables(t,_)}

            ${e.mainStart()}
              ${e.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.outputSize")}

              let indices = ${_.offsetToIndices("global_idx")};
              var xIndices = ${_.offsetToIndices("global_idx")};

              var value = ${g}(${u});
              var pad = 0;
              ${x}
              ${b}
              ${$}
              ${s}

              output[global_idx] = value;
            }`}else{if(m)throw new Error("Pooling with kernelShape.length > 2 is not supported for NHWC format.");let b=n.kernelShape.length,x=n.pads.length,$="";return l?$=`
                if (xIndices[j] >= uniforms.x_shape[j]) {
                  pad++;
                  isPad = true;
                  break;
                }
              }
              if (!isPad) {
                let x_val = x[${t.indicesToOffset("xIndices")}];
                ${i}
              }`:$=`
              }
              let x_val = x[${t.indicesToOffset("xIndices")}];
              ${i}
            `,`
            ${e.registerUniforms(d).declareVariables(t,_)}

            ${e.mainStart()}
              ${e.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.outputSize")}
              let indices = ${_.offsetToIndices("global_idx")};
              var xIndices = ${_.offsetToIndices("global_idx")};

              var offsets: array<u32, ${b}>;

              var value = ${g}(${u});
              var pad = 0;
              var isPad = false;

              for (var i: u32 = 0u; i < uniforms.kernelSize; i++) {
                var offset = i;
                for (var j = 0u; j < ${b-1}u; j++) {
                  offsets[j] = offset / ${j("uniforms.kernelStrides","j",b)};
                  offset -= offsets[j] * ${j("uniforms.kernelStrides","j",b)};
                }
                offsets[${b-1}] = offset;

                isPad = false;
                for (var j = ${r-b}u; j < ${r}u; j++) {
                  xIndices[j] = indices[j] * ${j("uniforms.strides",`j - ${r-b}u`,b)}
                    + offsets[j - ${r-b}u] - ${j("uniforms.pads","j - 2u",x)};
                  ${$}
              }
              ${s}

              output[global_idx] = value;
            }`}},Qi=e=>`${e.format};${e.ceilMode};${e.autoPad};${e.kernelShape.length}`,ol=e=>`${Qi(e)};${e.countIncludePad}`,ul=e=>`${Qi(e)};${e.storageOrder};${e.dilations}`,Xi=e=>({format:e.format,autoPad:["NOTSET","VALID","SAME_UPPER","SAME_LOWER"][e.auto_pad],ceilMode:e.ceil_mode,kernelShape:e.kernel_shape,strides:e.strides,pads:e.pads}),Yi=(e,t,r,a)=>{let[n,i]=ji(t,a,r),s=R("x",t.dataType,t.dims.length),u=s.type.value,d="value += x_val;",l="";n.countIncludePad?l+=`value /= ${u}(uniforms.kernelSize);`:l+=`value /= ${u}(i32(uniforms.kernelSize) - pad);`;let[c,f,m,g,_]=Ki(i,n);c.push(...Q(t.dims,i));let b=["rank"];return{name:e,shaderCache:{hint:`${a.cacheKey};${m};${g};${_}`,inputDependencies:b},getRunData:()=>({outputs:[{dims:i,dataType:t.dataType}],dispatchGroup:{x:Math.ceil(O.size(i)/64)},programUniforms:c}),getShaderSource:x=>Zi(x,s,t.dims.length,i.length,n,d,l,0,f,m,g,_)}},jc=e=>{let t=e.count_include_pad!==0,r=Xi(e);if(r.ceilMode!==0)throw new Error("using ceil() in shape computation is not yet supported for AveragePool");let a={countIncludePad:t,...r,cacheKey:""};return{...a,cacheKey:ol(a)}},Kc=(e,t)=>{Xt(e.inputs),e.compute(Yi("AveragePool",e.inputs[0],!1,t))},Ji={autoPad:"",ceilMode:0,countIncludePad:!1,kernelShape:[],strides:[],pads:[],storageOrder:0,dilations:[]},Zc=e=>{let t=e.format;return{format:t,...Ji,cacheKey:t}},Qc=(e,t)=>{Xt(e.inputs),e.compute(Yi("GlobalAveragePool",e.inputs[0],!0,t))},ea=(e,t,r,a)=>{let[n,i]=ji(t,a,r),s=`
      value = max(x_val, value);
    `,u="",d=R("x",t.dataType,t.dims.length),l=["rank"],[c,f,m,g,_]=Ki(i,n);return c.push(...Q(t.dims,i)),{name:e,shaderCache:{hint:`${a.cacheKey};${m};${g};${_}`,inputDependencies:l},getRunData:()=>({outputs:[{dims:i,dataType:t.dataType}],dispatchGroup:{x:Math.ceil(O.size(i)/64)},programUniforms:c}),getShaderSource:b=>Zi(b,d,t.dims.length,i.length,n,s,u,t.dataType===10?-65504:-1e5,f,m,g,_)}},Xc=(e,t)=>{Xt(e.inputs),e.compute(ea("MaxPool",e.inputs[0],!1,t))},Yc=e=>{let t=e.storage_order,r=e.dilations,a=Xi(e);if(t!==0)throw new Error("column major storage order is not yet supported for MaxPool");if(a.ceilMode!==0)throw new Error("using ceil() in shape computation is not yet supported for MaxPool");let n={storageOrder:t,dilations:r,...a,cacheKey:""};return{...n,cacheKey:ul(n)}},Jc=e=>{let t=e.format;return{format:t,...Ji,cacheKey:t}},ef=(e,t)=>{Xt(e.inputs),e.compute(ea("GlobalMaxPool",e.inputs[0],!0,t))}}),ll,dl,tf,rf,og=P(()=>{ee(),ae(),ve(),ne(),ll=(e,t)=>{if(e.length<2||e.length>3)throw new Error("DequantizeLinear requires 2 or 3 inputs.");if(e.length===3&&e[1].dims===e[2].dims)throw new Error("x-scale and x-zero-point must have the same shape.");if(e.length===3&&e[0].dataType!==e[2].dataType)throw new Error("x and x-zero-point must have the same data type.");if(e[0].dataType===6&&e.length>2)throw new Error("In the case of dequantizing int32 there is no zero point.");if(e[1].dims.length!==0&&e[1].dims.length!==1&&e[1].dims.length!==e[0].dims.length)throw new Error("scale input must be a scalar, a 1D tensor, or have the same rank as the input tensor.");if(e.length>2){if(e[0].dataType!==e[2].dataType)throw new Error("x and x-zero-point must have the same data type.");if(e[1].dims.length!==e[2].dims.length)throw new Error("scale and zero-point inputs must have the same rank.");if(!e[1].dims.map((r,a)=>r===e[2].dims[a]).reduce((r,a)=>r&&a,!0))throw new Error("scale and zero-point inputs must have the same shape.")}if(t.blockSize>0){if(e[1].dims.length===0||e[1].dims.length===1&&e[1].dims[0]===1)throw new Error("blockSize must be set only for block quantization.");if(!e[1].dims.map((n,i)=>i===t.axis||n===e[0].dims[i]).reduce((n,i)=>n&&i,!0))throw new Error("For block qunatization, scale input shape to match the input shape except for the axis");if(e[1].dims.length!==e[0].dims.length)throw new Error("For block qunatization the scale input rank must be the same as the x rank.");let r=e[0].dims[t.axis],a=e[1].dims[t.axis];if(t.blockSize<Math.ceil(r/a)||t.blockSize>Math.ceil(r/(a-1)-1))throw new Error("blockSize must be with in the range [ceil(dI / Si), ceil(dI / (Si - 1) - 1)].")}},dl=(e,t)=>{let r=O.normalizeAxis(t.axis,e[0].dims.length),a=e[0].dataType,n=a===3,i=e[0].dims,s=e[1].dataType,u=O.size(i),d=a===3||a===2,l=d?[Math.ceil(O.size(e[0].dims)/4)]:e[0].dims,c=e[1].dims,f=e.length>2?e[2]:void 0,m=f?d?[Math.ceil(O.size(f.dims)/4)]:f.dims:void 0,g=c.length===0||c.length===1&&c[0]===1,_=g===!1&&c.length===1,b=$e(u),x=g&&(!d||b===4),$=x?b:1,w=x&&!d?b:1,S=R("input",d?12:a,l.length,w),k=R("scale",s,c.length),T=f?R("zero_point",d?12:a,m.length):void 0,E=H("output",s,i.length,$),z=[S,k];T&&z.push(T);let C=[l,c];f&&C.push(m);let A=[{type:12,data:u/$},{type:12,data:r},{type:12,data:t.blockSize},...Q(...C,i)],q=X=>{let G=[{name:"output_size",type:"u32"},{name:"axis",type:"u32"},{name:"block_size",type:"u32"}];return`
      ${X.registerUniforms(G).declareVariables(...z,E)}
      ${X.mainStart()}
          ${X.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}
          let output_indices = ${E.offsetToIndices("global_idx")};

          // Set input x
          ${d?`
            let input = ${S.getByOffset("global_idx / 4")};
            let x_vec = ${n?"unpack4xI8(input)":"unpack4xU8(input)"};
            let x_value = ${$===1?"x_vec[global_idx % 4]":"x_vec"};`:`let x_value = ${S.getByOffset("global_idx")};`};

          // Set scale input
          ${g?`let scale_value= ${k.getByOffset("0")}`:_?`
            let scale_index = ${E.indicesGet("output_indices","uniforms.axis")};
            let scale_value= ${k.getByOffset("scale_index")};`:`
            var scale_indices: ${k.type.indices} = output_indices;
            let index = ${k.indicesGet("scale_indices","uniforms.axis")} / uniforms.block_size;
            ${k.indicesSet("scale_indices","uniforms.axis","index")};
            let scale_value= ${k.getByIndices("scale_indices")};`};

          // Set zero-point input
          ${T?g?d?`
                let zero_point_input = ${T.getByOffset("0")};
                let zero_point_vec =  ${n?"unpack4xI8(zero_point_input)":"unpack4xU8(zero_point_input)"};
                let zero_point_value= zero_point_vec[0]`:`let zero_point_value = ${T.getByOffset("0")}`:_?d?`
                let zero_point_index = ${E.indicesGet("output_indices","uniforms.axis")};
                let zero_point_input = ${T.getByOffset("zero_point_index / 4")};
                let zero_point_vec =  ${n?"unpack4xI8(zero_point_input)":"unpack4xU8(zero_point_input)"};
                let zero_point_value = zero_point_vec[zero_point_index % 4]`:`
                let zero_point_index = ${E.indicesGet("output_indices","uniforms.axis")};
                let zero_point_value = ${T.getByOffset("zero_point_index")};`:d?`
                let zero_point_offset = ${k.indicesToOffset("scale_indices")};
                let zero_point_input = ${T.getByOffset("zero_point_offset / 4")};
                let zero_point_vec = ${n?"unpack4xI8(zero_point_input)":"unpack4xU8(zero_point_input)"};
                let zero_point_value = zero_point_vec[zero_point_offset % 4];`:`let zero_point_value = ${T.getByIndices("scale_indices")};`:`let zero_point_value = ${d?n?"i32":"u32":S.type.value}(0);`};
      // Compute and write output
      ${E.setByOffset("global_idx",`${E.type.value}(x_value - zero_point_value) * scale_value`)};
      }`};return{name:"DequantizeLinear",shaderCache:{hint:t.cacheKey,inputDependencies:T?["rank","rank","rank"]:["rank","rank"]},getShaderSource:q,getRunData:()=>({outputs:[{dims:i,dataType:s}],dispatchGroup:{x:Math.ceil(u/$/64),y:1,z:1},programUniforms:A})}},tf=(e,t)=>{ll(e.inputs,t),e.compute(dl(e.inputs,t))},rf=e=>pe({axis:e.axis,blockSize:e.blockSize})}),pl,cl,af,ug=P(()=>{je(),ee(),ne(),pl=(e,t,r)=>{let a=e===t,n=e<t&&r<0,i=e>t&&r>0;if(a||n||i)throw new Error("Range these inputs' contents are invalid.")},cl=(e,t,r,a)=>{let n=Math.abs(Math.ceil((t-e)/r)),i=[n],s=n,u=[{type:12,data:s},{type:a,data:e},{type:a,data:r},...Q(i)],d=l=>{let c=H("output",a,i.length),f=c.type.value,m=[{name:"outputSize",type:"u32"},{name:"start",type:f},{name:"delta",type:f}];return`
        ${l.registerUniforms(m).declareVariables(c)}
        ${l.mainStart()}
        ${l.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.outputSize")}
        output[global_idx] = uniforms.start + ${f}(global_idx) * uniforms.delta;
      }`};return{name:"Range",shaderCache:{hint:`${a}`},getShaderSource:d,getRunData:()=>({outputs:[{dims:i,dataType:a}],dispatchGroup:{x:Math.ceil(s/64)},programUniforms:u})}},af=e=>{let t=0,r=0,a=0;e.inputs[0].dataType===6?(t=e.inputs[0].getInt32Array()[0],r=e.inputs[1].getInt32Array()[0],a=e.inputs[2].getInt32Array()[0]):e.inputs[0].dataType===1&&(t=e.inputs[0].getFloat32Array()[0],r=e.inputs[1].getFloat32Array()[0],a=e.inputs[2].getFloat32Array()[0]),_e.webgpu.validateInputContent&&pl(t,r,a),e.compute(cl(t,r,a,e.inputs[0].dataType),{inputs:[]})}}),fl,ta,ra,hl,nf,sf,lg=P(()=>{ee(),ae(),ve(),ne(),fl=(e,t,r,a)=>{if(e!=="none"&&a!=="i32"&&a!=="u32"&&a!=="f32")throw new Error(`Input ${a} is not supported with reduction ${e}.`);let n=`{
                var oldValue = 0;
                loop {
                  let newValueF32 =`,i=`;
                  let newValue = bitcast<i32>(newValueF32);
                  let res = atomicCompareExchangeWeak(&${t}, oldValue, newValue);
                  if res.exchanged {
                    break;
                  }
                  oldValue = res.old_value;
                }
              }`;switch(e){case"none":return`${t}=${r};`;case"add":return a==="i32"||a==="u32"?`atomicAdd(&${t}, bitcast<${a}>(${r}));`:`
              ${n}bitcast<${a}>(oldValue) + (${r})${i}`;case"max":return a==="i32"||a==="u32"?`atomicMax(&${t}, bitcast<${a}>(${r}));`:`
                ${n}max(bitcast<f32>(oldValue), (${r}))${i}`;case"min":return a==="i32"||a==="u32"?`atomicMin(&${t}, bitcast<${a}>(${r}));`:`${n}min(bitcast<${a}>(oldValue), (${r}))${i}`;case"mul":return`${n}(bitcast<${a}>(oldValue) * (${r}))${i}`;default:throw new Error(`Reduction ${e} is not supported.`)}},ta=(e,t)=>`${e===1?`
    let element_count_dim = uniforms.output_strides;
    let dim_value = uniforms.output_shape;`:`
    let element_count_dim = uniforms.output_strides[${t?"i - indices_start":"i"}];
    let dim_value = uniforms.output_shape[${t?"i - indices_start":"i"} + uniforms.last_index_dimension];`}
    
    if (index >= 0) {
      if (index >= i32(dim_value)) {
        index = i32(dim_value - 1);
      }
    } else {
      if (index < -i32(dim_value)) {
        index = 0;
      } else {
        index += i32(dim_value);
      }
    }
    data_offset += u32((u32(index) * element_count_dim));`,ra=(e,t,r)=>`for (var i = 0u; i < uniforms.num_updates_elements; i++) {
        let value = updates[uniforms.num_updates_elements * ${r?"global_idx":"idx"} + i];
        ${fl(e.reduction,"output[data_offset + i]","value",t)}
      }`,hl=(e,t)=>{let r=e[0].dims,a=e[1].dims,n=r,i=1,s=Math.ceil(O.size(a)/i),u=a[a.length-1],d=O.sizeFromDimension(r,u),l=O.sizeFromDimension(a,0)/u,c=[{type:12,data:s},{type:12,data:u},{type:12,data:d},...Q(e[1].dims,e[2].dims,n)],f=m=>{let g=R("indices",e[1].dataType,e[1].dims.length),_=R("updates",e[2].dataType,e[2].dims.length,i),b=t.reduction!=="none"&&t.reduction!==""?Bd("output",e[0].dataType,n.length):H("output",e[0].dataType,n.length,i);return`
      ${m.registerUniform("output_size","u32").registerUniform("last_index_dimension","u32").registerUniform("num_updates_elements","u32").declareVariables(g,_,b)}
      ${m.mainStart()}
        ${m.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}
  var hasDuplicates = false;
  if (${t.reduction==="none"}) {
    for (var i = 0; i < ${l}; i = i + 1) {
      for (var j = i + 1; j < ${l}; j = j + 1) {
        var index_i = i32(indices[i].x);
        var index_j = i32(indices[j].x);
        if (index_i == index_j) {
          hasDuplicates = true;
          break;
        }
      }
      if (hasDuplicates) {
        break;
      }
    }
  }

  if (${t.reduction==="none"} && hasDuplicates) {
    if (global_idx != 0u) {
      return;
    }
    // Process each index-update pair individually when duplicates exist
    for (var idx = 0u; idx < ${l}u; idx++) {
      var data_offset = 0u;
      for (var i = 0u; i < uniforms.last_index_dimension; i++) {
        var index = i32(indices[idx * uniforms.last_index_dimension + i].x);
        ${ta(r.length,!1)}
      }
      ${ra(t,b.type.value,!1)}
    }
    return;
  }

  var data_offset = 0u;
  var indices_start = uniforms.last_index_dimension * global_idx;
  var indices_end = indices_start + uniforms.last_index_dimension;
  for (var i = indices_start; i < indices_end; i++) {
    var index = i32(indices[i].x);
    ${ta(r.length,!0)}
  }
  ${ra(t,b.type.value,!0)}
  }`};return{name:"ScatterND",shaderCache:{hint:`${t.cacheKey}_${t.reduction}`,inputDependencies:["rank","rank"]},getRunData:()=>({outputs:[{dims:n,dataType:e[0].dataType}],dispatchGroup:{x:Math.ceil(s/64)},programUniforms:c}),getShaderSource:f}},nf=e=>pe({reduction:e.reduction}),sf=(e,t)=>{e.compute(hl(e.inputs,t),{inputs:[e.inputs[1],e.inputs[2]],outputs:[]})}}),ml,gl,_l,ia,yl,bl,wl,$l,vl,xl,kl,Sl,aa,Tl,Il,El,zl,Cl,of,uf,dg=P(()=>{ee(),ae(),ve(),ne(),ml=(e,t)=>{if(e.every(r=>r>0||(()=>{throw new Error("Resize requires scales input values to be positive")})),e.length>0){if(t.mode==="linear"){if(!(e.length===2||e.length===3||e.length===4&&e[0]===1&&e[1]===1||e.length===4&&e[0]===1&&e[3]===1||e.length===5&&e[0]===1&&e[1]===1))throw new Error(`For linear mode, Resize requires scales to be 2D, 3D, 4D with either two outermost or one innermost and
            one outermost scale values equal to 1, or 5D with two outermost scale values equal to 1`)}else if(t.mode==="cubic"&&!(e.length===2||e.length===4&&e[0]===1&&e[1]===1||e.length===4&&e[0]===1&&e[3]===1))throw new Error("Resize requires scales input size to be 2 or 4 for cubic mode")}},gl=(e,t,r)=>{t.every(n=>n>=0&&n<r||(()=>{throw new Error("Resize requires axes input values to be positive and less than rank")}));let a=new Array(r).fill(1);return t.forEach((n,i)=>a[n]=e[i]),a},_l=(e,t,r,a,n,i)=>{let[s,u,d]=r>10?[1,2,3]:[-1,e.length>1?1:-1,-1],l=e[0].dims.length;if(s>0&&e.length>s&&e[s].dims.length>0)e[s].getFloat32Array().forEach(c=>i.push(c));else if(t.coordinateTransformMode==="tf_crop_and_resize")throw new Error("Resize requires RoI input to be specified when coordinateTransformMode is tfCropAndResize");if(u>0&&e.length>u&&e[u].dims.length===1&&e[u].dims[0]>0){if(e[u].getFloat32Array().forEach(c=>a.push(c)),a.length!==0&&a.length!==l&&r>=18&&a.length!==t.axes.length)throw new Error("Resize requires scales input size to be same as input rank or axes size for opset 18 and up");ml(a,t),t.axes.length>0&&gl(a,t.axes,l).forEach((c,f)=>a[f]=c)}if(d>0&&e.length>d&&e[d].dims.length===1&&e[d].dims[0]>0&&(e[d].getBigInt64Array().forEach(c=>n.push(Number(c))),n.length!==0&&n.length!==l&&r>=18&&n.length!==t.axes.length))throw new Error("Resize requires sizes input size to be same as input rank or axes size for opset 18 and up");if(t.axes.length>0){if(a.length!==0&&a.length!==t.axes.length)throw new Error('Resize requires "scales" input size to be of axes rank when axes attributes is specified');if(n.length!==0&&n.length!==t.axes.length)throw new Error('Resize requires "sizes" input size to be of rank axes rank when axes attributes is specified')}if(typeof a<"u"&&typeof n<"u"&&a.length>0&&n.length>l)throw new Error("Resize requires only of scales or sizes to be specified")},ia=(e,t,r,a)=>`
  // The whole part and the fractional part are calculated separately due to inaccuracy of floating
  // point division. As an example, f32(21) / f32(7) may evaluate to 2.99... instead of 3, causing an
  // offset-by-one error later in floor().
  let big = (${e}) * (${t});
  let whole = ${a}(big / (${r}));
  let fract = ${a}(big % (${r})) / ${a}(${r});
  return whole + fract;
`,yl=(e,t)=>`fn getOriginalCoordinateFromResizedCoordinate(xResized: u32, xScale: f32, lengthResized: u32,
     lengthOriginal: u32, roiStart: f32, roiEnd: f32) -> ${t} { `+(()=>{switch(e){case"asymmetric":return`
          if (xScale < 1.0 || floor(xScale) != xScale) {
            return ${t}(xResized) / ${t}(xScale);
          } else {
            ${ia("xResized","lengthOriginal","lengthResized",t)}
          }
        `;case"pytorch_half_pixel":return`if (lengthResized > 1) {
                    return (${t}(xResized) + 0.5) / ${t}(xScale) - 0.5;
                  } else {
                    return 0.0;
                  }`;case"tf_half_pixel_for_nn":return`return (${t}(xResized) + 0.5) / ${t}(xScale);`;case"align_corners":return`if (lengthResized == 1) {
                    return 0.0;
                  } else {
                    ${ia("xResized","lengthOriginal - 1","lengthResized - 1",t)}
                  }`;case"tf_crop_and_resize":return`if (lengthResized > 1) {
                    return ${t}(roiStart) * ${t}(lengthOriginal - 1) +
                        (${t}(xResized) * ${t}(roiEnd - roiStart) * ${t}(lengthOriginal - 1)) /
                        ${t}(lengthResized - 1);
                  } else {
                    return 0.5 * ${t}(roiStart + roiEnd) * ${t}(lengthOriginal - 1);
                  }`;case"half_pixel_symmetric":return`const outputWidth = ${t}xScale * ${t}(lengthResized);
                  const adjustment = ${t}(lengthResized) / outputWidth;
                  const center = ${t}(lengthOriginal) / 2;
                  const offset = center * (1 - adjustment);
                  return offset + ((${t}(xResized) + 0.5) / ${t}(xScale)) - 0.5;`;case"half_pixel":return`return ((${t}(xResized) + 0.5) / ${t}(xScale)) - 0.5;`;default:throw new Error(`Coordinate transform mode ${e} is not supported`)}})()+"}",bl=(e,t,r)=>`fn getNearestPixelFromOriginal(xOriginal: ${r}, isDownSample: bool) -> ${r} {`+(()=>{switch(e){case"round_prefer_ceil":return"if (fract(xOriginal) == 0.5) {             return ceil(xOriginal);           } else {             return round(xOriginal);           }";case"floor":return"return floor(xOriginal);";case"ceil":return"return ceil(xOriginal);";case"round_prefer_floor":return"if (fract(xOriginal) == 0.5) {                     return floor(xOriginal);                   } else {                     return round(xOriginal);                   }";case"simple":default:if(t<11)return"if (isDownSample)                     {                       return ceil(xOriginal);                     } else {                       return xOriginal;                     }";throw new Error(`Nearest mode ${e} is not supported`)}})()+"}",wl=(e,t,r)=>{let a=new Array(r).fill(0).concat(new Array(r).fill(1)),n=e.length===0?a:e.slice();return t.length>0?(t.forEach((i,s)=>{a[i]=n[s],a[s+r]=n[t.length+s]}),a):n},$l=(e,t,r,a)=>{let n=[];if(r.length>0)if(a.length>0){if(e.forEach(i=>n.push(i)),Math.max(...a)>e.length)throw new Error("axes is out of bound");a.forEach((i,s)=>n[i]=r[s])}else r.forEach(i=>n.push(i));else{if(t.length===0)throw new Error("Resize requires either scales or sizes.");n=e.map((i,s)=>Math.round(i*t[s]))}return n},vl=(e,t,r)=>{let a=(()=>{switch(r.keepAspectRatioPolicy){case"not_larger":return r.axes.length>0?Math.min(...r.axes.map(i=>t[i]),Number.MAX_VALUE):Math.min(...t,Number.MAX_VALUE);case"not_smaller":return r.axes.length>0?Math.max(...r.axes.map(i=>t[i]),Number.MIN_VALUE):Math.max(...t,Number.MIN_VALUE);default:throw new Error(`Keep aspect ratio policy ${r.keepAspectRatioPolicy} is not supported`)}})();t.fill(1,0,t.length);let n=e.slice();return r.axes.length>0?(r.axes.forEach(i=>t[i]=a),r.axes.forEach(i=>n[i]=Math.round(e[i]*t[i]))):(t.fill(a,0,t.length),n.forEach((i,s)=>n[s]=Math.round(i*t[s]))),n},xl=(e,t,r,a,n)=>`
    fn calculateOriginalIndicesFromOutputIndices(output_indices: ${e.type.indices}) -> array<${e.type.value}, ${r.length}> {
      var original_indices: array<${e.type.value}, ${r.length}>;
      for (var i:u32 = 0; i < ${r.length}; i++) {
        var output_index = ${e.indicesGet("output_indices","i")};
        var scale = ${j("uniforms.scales","i",a)};
        var roi_low = ${j("uniforms.roi","i",n)};
        var roi_hi = ${j("uniforms.roi",`i + ${t.length}`,n)};
        if (scale == 1.0) {
          original_indices[i] = ${e.type.value}(output_index);
        } else {
          var input_shape_i = ${j("uniforms.input_shape","i",t.length)};
          var output_shape_i = ${j("uniforms.output_shape","i",r.length)};
          original_indices[i] = getOriginalCoordinateFromResizedCoordinate(output_index, scale, output_shape_i,
                                                                           input_shape_i, roi_low, roi_hi);
        }
      }
      return original_indices;
    }`,kl=(e,t,r,a,n,i,s)=>`
    fn calculateInputIndicesFromOutputIndices(output_indices: ${t.type.indices}) -> ${e.type.indices} {
      var input_indices: ${e.type.indices};
      for (var i:u32 = 0; i < ${a.length}; i++) {
        var output_index = ${t.indicesGet("output_indices","i")};
        var input_index: u32;
        var scale = ${j("uniforms.scales","i",n)};
        if (scale == 1.0) {
          input_index = output_index;
        } else {
          var roi_low = ${j("uniforms.roi","i",i)};
          var roi_hi = ${j("uniforms.roi",`i + ${r.length}`,i)};
          var input_shape_i = ${j("uniforms.input_shape","i",r.length)};
          var output_shape_i = ${j("uniforms.output_shape","i",a.length)};
          var original_idx = getOriginalCoordinateFromResizedCoordinate(output_index, scale, output_shape_i,
                                                                        input_shape_i, roi_low, roi_hi);
          if (!${s} || (original_idx >= 0 && original_idx < ${t.type.value}(input_shape_i))) {
            if (original_idx < 0) {
              input_index = 0;
            } else if (original_idx > ${t.type.value}(input_shape_i - 1)) {
              input_index = input_shape_i - 1;
            } else {
              input_index = u32(getNearestPixelFromOriginal(original_idx, scale < 1));
            }
          } else {
            input_index = u32(original_idx);
          }
        }
        ${e.indicesSet("input_indices","i","input_index")}
      }
      return input_indices;
    }`,Sl=(e,t)=>`
    fn checkInputIndices(input_indices: ${e.type.indices}) -> bool {
      for (var i:u32 = 0; i < ${t.length}; i++) {
        var input_index = ${e.indicesGet("input_indices","i")};
        if (input_index < 0 || input_index >= ${j("uniforms.input_shape","i",t.length)}) {
          return false;
        }
      }
      return true;
    }`,aa=(e,t,r,a)=>e.rank>a?`
    ${e.indicesSet("input_indices",t,"channel")};
    ${e.indicesSet("input_indices",r,"batch")};
`:"",Tl=(e,t,r,a,n)=>{let[i,s,u,d]=r.length===2?[-1,0,1,-1]:[0,2,3,1],l=e.type.value;return`
    fn getInputValue(batch: u32, channel: u32, row: u32, col: u32) -> ${l} {
      var input_indices: ${e.type.indices};
      ${e.indicesSet("input_indices",s,`max(0, min(row, ${r[s]} - 1))`)};
      ${e.indicesSet("input_indices",u,`max(0, min(col, ${r[u]} - 1))`)};
      ${aa(e,d,i,2)}
      return ${e.getByIndices("input_indices")};
    }

    fn bilinearInterpolation(output_indices: ${t.type.indices}) -> ${l} {
      var originalIndices = calculateOriginalIndicesFromOutputIndices(output_indices);
      var row:${l} = originalIndices[${s}];
      var col:${l} = originalIndices[${u}];
      ${a?`if (row < 0 || row > (${r[s]} - 1) || col < 0 || col > (${r[u]} - 1)) {
        return ${n};
      }`:""};
      row = max(0, min(row, ${r[s]} - 1));
      col = max(0, min(col, ${r[u]} - 1));
      var row1: u32 = u32(row);
      var col1: u32 = u32(col);
      var row2: u32 = u32(row + 1);
      var col2: u32 = u32(col + 1);
      var channel: u32 = ${r.length>2?`u32(originalIndices[${d}])`:"0"};
      var batch: u32 =  ${r.length>2?`u32(originalIndices[${i}])`:"0"};
      var x11: ${l} = getInputValue(batch, channel, row1, col1);
      var x12: ${l} = getInputValue(batch, channel, row1, col2);
      var x21: ${l} = getInputValue(batch, channel, row2, col1);
      var x22: ${l} = getInputValue(batch, channel, row2, col2);
      var dx1: ${l} = abs(row - ${l}(row1));
      var dx2: ${l} = abs(${l}(row2) - row);
      var dy1: ${l} = abs(col - ${l}(col1));
      var dy2: ${l} = abs(${l}(col2) - col);
      if (row1 == row2) {
        dx1 = 0.5;
        dx2 = 0.5;
      }
      if (col1 == col2) {
        dy1 = 0.5;
        dy2 = 0.5;
      }
      return (x11 * dx2 * dy2 + x12 * dx2 * dy1 + x21 * dx1 * dy2 + x22 * dx1 * dy1);
    }`},Il=(e,t,r,a,n,i,s,u,d,l)=>{let c=r.length===2,[f,m]=c?[0,1]:[2,3],g=e.type.value,_=b=>{let x=b===f?"row":"col";return`
      fn ${x}CubicInterpolation(input_indices: ${e.type.indices}, output_indices: ${t.type.indices}) -> ${g} {
        var output_index = ${t.indicesGet("output_indices",b)};
        var originalIdx: ${g} = getOriginalCoordinateFromResizedCoordinate(output_index, ${n[b]},
        ${a[b]}, ${r[b]}, ${i[b]}, ${i[b]} + ${r.length});
        var fractOriginalIdx: ${g} = originalIdx - floor(originalIdx);
        var coefs = getCubicInterpolationCoefs(fractOriginalIdx);

        if (${u} && (originalIdx < 0 || originalIdx > (${r[b]} - 1))) {
          return ${d};
        }
        var data: array<${g}, 4> = array<${g}, 4>(0.0, 0.0, 0.0, 0.0);
        for (var i: i32 = -1; i < 3; i++) {
          var ${x}: ${g} = originalIdx + ${g}(i);
          if (${x} < 0 || ${x} >= ${r[b]}) {
            ${l?`coefs[i + 1] = 0.0;
                        continue;`:u?`return ${d};`:`${x} = max(0, min(${x}, ${r[b]} - 1));`};
          }
        var input_indices_copy: ${e.type.indices} = input_indices;
          ${e.indicesSet("input_indices_copy",b,`u32(${x})`)};
          data[i + 1] = ${b===f?e.getByIndices("input_indices_copy"):"rowCubicInterpolation(input_indices_copy, output_indices)"};
        }
        return cubicInterpolation1D(data, coefs);
      }`};return`
    ${_(f)};
    ${_(m)};
  fn getCubicInterpolationCoefs(s: ${g}) -> array<${g}, 4> {
    var absS = abs(s);
    var coeffs: array<${g}, 4> = array<${g}, 4>(0.0, 0.0, 0.0, 0.0);
    var oneMinusAbsS: ${g} = 1.0 - absS;
    var twoMinusAbsS: ${g} = 2.0 - absS;
    var onePlusAbsS: ${g} = 1.0 + absS;
    coeffs[0] = ((${s} * onePlusAbsS - 5 * ${s}) * onePlusAbsS + 8 * ${s}) * onePlusAbsS - 4 * ${s};
    coeffs[1] = ((${s} + 2) * absS - (${s} + 3)) * absS * absS + 1;
    coeffs[2] = ((${s} + 2) * oneMinusAbsS - (${s} + 3)) * oneMinusAbsS * oneMinusAbsS + 1;
    coeffs[3] = ((${s} * twoMinusAbsS - 5 * ${s}) * twoMinusAbsS + 8 * ${s}) * twoMinusAbsS - 4 * ${s};
    return coeffs;
  }

  fn cubicInterpolation1D(x: array<${g}, 4>, coefs: array<${g}, 4>) -> ${g} {
    var coefsSum: ${g} = coefs[0] + coefs[1] + coefs[2] + coefs[3];
    return (x[0] * coefs[0] + x[1] * coefs[1]+ x[2] * coefs[2]+ x[3] * coefs[3]) / coefsSum;
  }

  fn bicubicInterpolation(output_indices: ${t.type.indices}) -> ${g} {
    var input_indices: ${e.type.indices} = output_indices;
    return colCubicInterpolation(input_indices, output_indices);
  }
    `},El=(e,t,r,a,n)=>{let[i,s,u,d,l]=r.length===3?[-1,0,1,2,-1]:[0,2,3,4,1],c=e.type.value;return`
    fn getInputValue(batch: u32, channel: u32, depth:u32, height: u32, width: u32) -> ${c} {
      var input_indices: ${e.type.indices};
      ${e.indicesSet("input_indices",s,`max(0, min(depth, ${r[s]} - 1))`)};
      ${e.indicesSet("input_indices",u,`max(0, min(height, ${r[u]} - 1))`)};
      ${e.indicesSet("input_indices",d,`max(0, min(width, ${r[d]} - 1))`)};
      ${aa(e,l,i,3)}
      return ${e.getByIndices("input_indices")};
    }

    fn trilinearInterpolation(output_indices: ${t.type.indices}) -> ${c} {
      var originalIndices = calculateOriginalIndicesFromOutputIndices(output_indices);
      var depth:${c} = originalIndices[${s}];
      var height:${c} = originalIndices[${u}];
      var width:${c} = originalIndices[${d}];
      ${a?`if (depth < 0 || depth > (${r[s]} - 1) || height < 0 || height > (${r[u]} - 1) || width < 0 || (width > ${r[d]} - 1)) {
      return ${n};
        }`:""};

    depth = max(0, min(depth, ${r[s]} - 1));
      height = max(0, min(height, ${r[u]} - 1));
      width = max(0, min(width, ${r[d]} - 1));
      var depth1: u32 = u32(depth);
      var height1: u32 = u32(height);
      var width1: u32 = u32(width);
      var depth2: u32 = u32(depth + 1);
      var height2: u32 = u32(height + 1);
      var width2: u32 = u32(width + 1);
      var channel: u32 = ${r.length>3?`u32(originalIndices[${l}])`:"0"};
      var batch: u32 =  ${r.length>3?`u32(originalIndices[${i}])`:"0"};

      var x111: ${c} = getInputValue(batch, channel, depth1, height1, width1);
      var x112: ${c} = getInputValue(batch, channel, depth1, height1, width2);
      var x121: ${c} = getInputValue(batch, channel, depth1, height2, width1);
      var x122: ${c} = getInputValue(batch, channel, depth1, height2, width2);
      var x211: ${c} = getInputValue(batch, channel, depth2, height1, width1);
      var x212: ${c} = getInputValue(batch, channel, depth2, height1, width2);
      var x221: ${c} = getInputValue(batch, channel, depth2, height2, width1);
      var x222: ${c} = getInputValue(batch, channel, depth2, height2, width2);
      var dx1: ${c} = abs(depth - ${c}(depth1));
      var dx2: ${c} = abs(${c}(depth2) - depth);
      var dy1: ${c} = abs(height - ${c}(height1));
      var dy2: ${c} = abs(${c}(height2) - height);
      var dz1: ${c} = abs(width - ${c}(width1));
      var dz2: ${c} = abs(${c}(width2) - width);
      if (depth1 == depth2) {
        dx1 = 0.5;
        dx2 = 0.5;
      }
      if (height1 == height2) {
        dy1 = 0.5;
        dy2 = 0.5;
      }
      if (width1 == width2) {
        dz1 = 0.5;
        dz2 = 0.5;
      }
      return (x111 * dx2 * dy2 * dz2 + x112 * dx2 * dy2 * dz1 + x121 * dx2 * dy1 *dz2 + x122 * dx2 * dy1 * dz1 +
              x211 * dx1 * dy2 * dz2 + x212 * dx1 * dy2 * dz1 + x221 * dx1 * dy1 *dz2 + x222 * dx1 * dy1 * dz1);
    }`},zl=(e,t,r,a,n,i)=>{let s=e.dims,u=wl(i,t.axes,s.length),d=$l(s,a,n,t.axes),l=a.slice();a.length===0&&(l=s.map((w,S)=>w===0?1:d[S]/w),t.keepAspectRatioPolicy!=="stretch"&&(d=vl(s,l,t)));let c=H("output",e.dataType,d.length),f=R("input",e.dataType,s.length),m=O.size(d),g=s.length===d.length&&s.every((w,S)=>w===d[S]),_=t.coordinateTransformMode==="tf_crop_and_resize",b=t.extrapolationValue,x=f.type.value,$=w=>`
      ${g?"":`
      ${yl(t.coordinateTransformMode,x)};
      ${(()=>{switch(t.mode){case"nearest":return`
              ${Sl(f,s)};
              ${bl(t.nearestMode,r,x)};
              ${kl(f,c,s,d,l.length,u.length,_)};
              `;case"linear":return`
              ${xl(c,s,d,l.length,u.length)};
              ${(()=>{if(s.length===2||s.length===4)return`${Tl(f,c,s,_,b)}`;if(s.length===3||s.length===5)return`${El(f,c,s,_,b)}`;throw Error("Linear mode only supports input dims 2, 3, 4 and 5 are supported in linear mode.")})()};
            `;case"cubic":return`
            ${(()=>{if(s.length===2||s.length===4)return`${Il(f,c,s,d,l,u,t.cubicCoeffA,_,t.extrapolationValue,t.excludeOutside)}`;throw Error("Cubic mode only supports input dims 2 and 4 are supported in linear mode.")})()};
            `;default:throw Error("Invalid resize mode")}})()};
      `}
      ${w.registerUniform("output_size","u32").registerUniform("scales","f32",l.length).registerUniform("roi","f32",u.length).declareVariables(f,c)}
      ${w.mainStart()}
        ${w.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}
        ${g?"output[global_idx] = input[global_idx];":`
        let output_indices = ${c.offsetToIndices("global_idx")};
        var input_indices: ${f.type.indices};
        ${(()=>{switch(t.mode){case"nearest":return`input_indices = calculateInputIndicesFromOutputIndices(output_indices);
                if (checkInputIndices(input_indices)) {
                  output[global_idx] = ${f.getByIndices("input_indices")};
                } else {
                  output[global_idx] = ${t.extrapolationValue};
                }`;case"linear":return`output[global_idx] = ${s.length===2||s.length===4?"bilinearInterpolation":"trilinearInterpolation"}(output_indices);`;case"cubic":return"output[global_idx] = bicubicInterpolation(output_indices);";default:throw Error(`Unsupported resize mode: ${t.mode}`)}})()};
`}
      }`;return{name:"Resize",shaderCache:{hint:`${t.cacheKey}|${r}|${l.length>0?t.mode==="cubic"?l:l.length:""}|${n.length>0?n:""}|${u.length>0?u:""}|${g}|${t.mode==="nearest"?s.length:s}`,inputDependencies:["rank"]},getShaderSource:$,getRunData:()=>({outputs:[{dims:d,dataType:e.dataType}],dispatchGroup:{x:Math.ceil(m/64)},programUniforms:[{type:12,data:m},{type:1,data:l},{type:1,data:u},...Q(s,d)]})}},Cl=e=>{let t=e.customDataBuffer;return new Uint32Array(t,t.byteOffset,1)[0]},of=(e,t)=>{let r=[],a=[],n=[],i=Cl(e);if(t.antialias!==0)throw Error("Only default value (0) for Antialias attribute is supported");_l(e.inputs,t,i,r,a,n),e.compute(zl(e.inputs[0],t,i,r,a,n),{inputs:[0]})},uf=e=>{let t=e.antialias,r=e.axes,a=e.coordinateTransformMode,n=e.cubicCoeffA,i=e.excludeOutside!==0,s=e.extrapolationValue,u=e.keepAspectRatioPolicy,d=e.mode,l=e.nearestMode===""?"simple":e.nearestMode;return pe({antialias:t,axes:r,coordinateTransformMode:a,cubicCoeffA:n,excludeOutside:i,extrapolationValue:s,keepAspectRatioPolicy:u,mode:d,nearestMode:l})}}),Ol,Al,lf,pg=P(()=>{ee(),ae(),ne(),Ol=e=>{if(!e||e.length<3)throw new Error("layerNorm requires at least 3 inputs.");let t=e[0],r=e[1],a=e[2];if(t.dataType!==r.dataType||t.dataType!==a.dataType)throw new Error("All inputs must have the same data type");if(t.dims.length!==3&&t.dims.length!==2)throw new Error("Input must be 2D or 3D");if(r.dims.length!==3&&r.dims.length!==2)throw new Error("Skip must be 2D or 3D");let n=t.dims[t.dims.length-1],i=t.dims[t.dims.length-2];if(r.dims[r.dims.length-1]!==n)throw new Error("Skip must have the same hidden size as input");if(r.dims[r.dims.length-2]!==i)throw new Error("Skip must have the same sequence length as input");if(a.dims.length!==1)throw new Error("Gamma must be 1D");if(a.dims[a.dims.length-1]!==n)throw new Error("Gamma must have the same hidden size as input");if(e.length>3){let s=e[3];if(s.dims.length!==1)throw new Error("Beta must be 1D");if(s.dims[s.dims.length-1]!==n)throw new Error("Beta must have the same hidden size as input")}if(e.length>4){let s=e[4];if(s.dims.length!==1)throw new Error("Bias must be 1D");if(s.dims[s.dims.length-1]!==n)throw new Error("Bias must have the same hidden size as input")}},Al=(e,t,r,a)=>{let n=t.simplified,i=e[0].dims,s=O.size(i),u=i,d=s,l=i.slice(-1)[0],c=a?i.slice(0,-1).concat(1):[],f=!n&&e.length>3,m=e.length>4,g=a&&r>1,_=a&&r>2,b=r>3,x=64,$=$e(l),w=[{type:12,data:d},{type:12,data:$},{type:12,data:l},{type:1,data:t.epsilon}],S=T=>{let E=[{name:"output_size",type:"u32"},{name:"components",type:"u32"},{name:"hidden_size",type:"u32"},{name:"epsilon",type:"f32"}],z=[R("x",e[0].dataType,e[0].dims,$),R("skip",e[1].dataType,e[1].dims,$),R("gamma",e[2].dataType,e[2].dims,$)];f&&z.push(R("beta",e[3].dataType,e[3].dims,$)),m&&z.push(R("bias",e[4].dataType,e[4].dims,$)),z.push(H("output",e[0].dataType,u,$)),g&&z.push(H("mean_output",1,c)),_&&z.push(H("inv_std_output",1,c)),b&&z.push(H("input_skip_bias_sum",e[0].dataType,u,$));let C=ke(e[0].dataType),A=ke(1,$);return`

      ${T.registerUniforms(E).declareVariables(...z)}
      var<workgroup> sum_shared : array<${A}, ${x}>;
      var<workgroup> sum_squared_shared : array<${A}, ${x}>;

      ${T.mainStart([x,1,1])}
        let ix = local_id.x;
        let iy = global_id.x / ${x};

        let hidden_size_vectorized: u32 = uniforms.hidden_size / uniforms.components;
        var stride = hidden_size_vectorized / ${x};
        let offset = ix * stride + iy * hidden_size_vectorized;
        let offset1d = stride * ix;
        if (ix == ${x-1}) {
          stride = hidden_size_vectorized - stride * ix;
        }
        for (var i: u32 = 0; i < stride; i++) {
          let skip_value = skip[offset + i];
          let bias_value = ${m?"bias[offset1d + i]":C+"(0.0)"};
          let input_value = x[offset + i];
          let value = input_value + skip_value + bias_value;
          ${b?"input_skip_bias_sum[offset + i] = value;":""}
          output[offset + i] = value;
          let f32_value = ${Dt(C,$,"value")};
          sum_shared[ix] += f32_value;
          sum_squared_shared[ix] += f32_value * f32_value;
        }
        workgroupBarrier();

        var reduce_size : u32 = ${x};
        for (var curr_size = reduce_size >> 1;  curr_size > 0; curr_size = reduce_size >> 1) {
          reduce_size = curr_size + (reduce_size & 1);
          if (ix < curr_size) {
            sum_shared[ix] += sum_shared[ix + reduce_size];
            sum_squared_shared[ix] += sum_squared_shared[ix + reduce_size];
          }
          workgroupBarrier();
        }

        let sum = sum_shared[0];
        let square_sum = sum_squared_shared[0];
        let mean = ${mt("sum",$)} / f32(uniforms.hidden_size);
        let inv_std_dev = inverseSqrt(${mt("square_sum",$)} / f32(uniforms.hidden_size) ${n?"":"- mean * mean"} + uniforms.epsilon);
        ${g?"mean_output[global_idx] = mean;":""}
        ${_?"inv_std_output[global_idx] = inv_std_dev;":""}

        for (var i: u32 = 0; i < stride; i++) {
          output[offset + i] = (output[offset + i] ${n?"":`- ${C}(mean)`}) *
            ${C}(inv_std_dev) * gamma[offset1d + i]
            ${f?"+ beta[offset1d + i]":""};
        }
      }`},k=[{dims:u,dataType:e[0].dataType}];return r>1&&k.push({dims:c,dataType:1}),r>2&&k.push({dims:c,dataType:1}),r>3&&k.push({dims:i,dataType:e[0].dataType}),{name:"SkipLayerNormalization",shaderCache:{hint:`${$};${g};${_};${b}`,inputDependencies:e.map((T,E)=>"type")},getShaderSource:S,getRunData:()=>({outputs:k,dispatchGroup:{x:Math.ceil(d/l)},programUniforms:w})}},lf=(e,t)=>{Ol(e.inputs);let r=[0];e.outputCount>1&&r.push(-3),e.outputCount>2&&r.push(-3),e.outputCount>3&&r.push(3),e.compute(Al(e.inputs,t,e.outputCount,!1),{outputs:r})}}),Bl,Yt,Rl,na,Nl,Ml,df,pf,cg=P(()=>{ee(),ae(),ve(),ne(),Bl=(e,t)=>{if(!e||e.length<1)throw new Error("too few inputs");if(t.axes.length!==0){if(t.axes.length!==t.starts.length||t.axes.length!==t.ends.length)throw new Error("axes, starts and ends must have the same length")}else if(t.starts.length!==t.ends.length)throw new Error("starts and ends must have the same length");e.slice(1).forEach((r,a)=>{if(e[a+1].dataType!==6&&e[a+1].dataType!==7)throw new Error(`Input ${a} must be an array of int32 or int64`)})},Yt=(e,t)=>{let r=[];if(e.length>t)if(e[t].dataType===7)e[t].getBigInt64Array().forEach(a=>r.push(Number(a)));else if(e[t].dataType===6)e[t].getInt32Array().forEach(a=>r.push(Number(a)));else throw new Error(`Input ${t} must be an array of int32 or int64`);return r},Rl=(e,t)=>{if(e.length>1){let r=Yt(e,1),a=Yt(e,2),n=Yt(e,3);return n.length===0&&(n=[...Array(e[0].dims.length).keys()]),pe({starts:r,ends:a,axes:n})}else return t},na=(e,t,r,a,n)=>{let i=e;return e<0&&(i+=r[a[t]]),n[t]<0?Math.max(0,Math.min(i,r[a[t]]-1)):Math.max(0,Math.min(i,r[a[t]]))},Nl=(e,t,r)=>`fn calculateInputIndices(output_indices: ${t.type.indices}) -> ${e.type.indices} {
          var input_indices: ${e.type.indices};
          var carry = 0u;
          for (var i = ${r.length}; i >= 0; i--) {
            let input_shape_i = ${j("uniforms.input_shape","i",r.length)};
            let steps_i = ${j("uniforms.steps","i",r.length)};
            let signs_i = ${j("uniforms.signs","i",r.length)};
            let starts_i = ${j("uniforms.starts","i",r.length)};
            var output_index = ${t.indicesGet("output_indices","i")};
            var input_index = output_index * steps_i + starts_i + carry;
            carry = input_index / input_shape_i;
            input_index = input_index % input_shape_i;
            if (signs_i < 0) {
              input_index = input_shape_i - input_index - 1u + starts_i;
            }
            ${e.indicesSet("input_indices","i","input_index")};
          }
          return input_indices;
      }`,Ml=(e,t)=>{let r=e[0].dims,a=O.size(r),n=t.axes.length>0?O.normalizeAxes(t.axes,r.length):[...Array(r.length).keys()],i=Yt(e,4);i.forEach($=>$!==0||(()=>{throw new Error("step cannot be 0")})),i.length===0&&(i=Array(n.length).fill(1));let s=t.starts.map(($,w)=>na($,w,r,n,i)),u=t.ends.map(($,w)=>na($,w,r,n,i));if(n.length!==s.length||n.length!==u.length)throw new Error("start, ends and axes should have the same number of elements");if(n.length!==r.length)for(let $=0;$<r.length;++$)n.includes($)||(s.splice($,0,0),u.splice($,0,r[$]),i.splice($,0,1));let d=i.map($=>Math.sign($));i.forEach(($,w,S)=>{if($<0){let k=(u[w]-s[w])/$,T=s[w],E=T+k*i[w];s[w]=E,u[w]=T,S[w]=-$}});let l=r.slice(0);n.forEach(($,w)=>{l[$]=Math.ceil((u[$]-s[$])/i[$])});let c={dims:l,dataType:e[0].dataType},f=H("output",e[0].dataType,l.length),m=R("input",e[0].dataType,e[0].dims.length),g=O.size(l),_=[{name:"outputSize",type:"u32"},{name:"starts",type:"u32",length:s.length},{name:"signs",type:"i32",length:d.length},{name:"steps",type:"u32",length:i.length}],b=[{type:12,data:g},{type:12,data:s},{type:6,data:d},{type:12,data:i},...Q(e[0].dims,l)],x=$=>`
      ${$.registerUniforms(_).declareVariables(m,f)}
        ${Nl(m,f,r)}
        ${$.mainStart()}
          ${$.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.outputSize")}
          let output_indices = ${f.offsetToIndices("global_idx")};
          let input_indices = calculateInputIndices(output_indices);
          ${f.setByOffset("global_idx",m.getByIndices("input_indices"))}
      }`;return{name:"Slice",shaderCache:{hint:`${d.length}_${s.length}_${i.length}`,inputDependencies:["rank"]},getShaderSource:x,getRunData:()=>({outputs:[c],dispatchGroup:{x:Math.ceil(a/64)},programUniforms:b})}},df=(e,t)=>{Bl(e.inputs,t);let r=Rl(e.inputs,t);e.compute(Ml(e.inputs,r),{inputs:[0]})},pf=e=>{let t=e.starts,r=e.ends,a=e.axes;return pe({starts:t,ends:r,axes:a})}}),Dl,Pl,cf,ff,fg=P(()=>{ee(),ae(),ve(),gt(),ne(),Dl=e=>{if(!e||e.length!==1)throw new Error("Softmax op requires 1 input.")},Pl=(e,t)=>{let r=e.inputs[0],a=r.dims,n=O.size(a),i=a.length,s=O.normalizeAxis(t.axis,i),u=s<a.length-1,d,l=[];u?(l=Array.from({length:i},(z,C)=>C),l[s]=i-1,l[i-1]=s,d=e.compute(Me(r,l),{inputs:[r],outputs:[-1]})[0]):d=r;let c=d.dims,f=c[i-1],m=n/f,g=$e(f),_=f/g,b=64;m===1&&(b=256);let x=(z,C)=>C===4?`max(max(${z}.x, ${z}.y), max(${z}.z, ${z}.w))`:C===2?`max(${z}.x, ${z}.y)`:C===3?`max(max(${z}.x, ${z}.y), ${z}.z)`:z,$=R("x",d.dataType,d.dims,g),w=H("result",d.dataType,d.dims,g),S=$.type.value,k=ke(d.dataType)==="f32"?`var threadMax = ${S}(-3.402823e+38f);`:`var threadMax = ${S}(-65504.0h);`,T=z=>`
      var<workgroup> rowMaxShared : ${S};
      var<workgroup> rowSumShared : ${S};
      var<workgroup> threadShared : array<${S}, ${b}>;

      fn getValue(row: i32, col: i32, row_stride: i32) -> ${S} {
        let index = row * row_stride + col;
        return x[index];
      }

      fn setValue(row: i32, col: i32, row_stride: i32, value: ${S}) {
        let index = row * row_stride + col;
        result[index] = value;
      }
      ${z.registerUniform("packedCols","i32").declareVariables($,w)}
      ${z.mainStart(b)}
        let gindex = i32(global_idx);
        let lindex = i32(local_idx);
        const wg = ${b};
        let row = gindex / wg;
        let cols = uniforms.packedCols;
        let row_stride : i32 = uniforms.packedCols;

        // find the rows max
        ${k}
        for (var col = lindex; col < cols; col += wg) {
          let value = getValue(row, col, row_stride);
          threadMax = max(threadMax, value);
        }
        if (lindex < cols) {
          threadShared[lindex] = threadMax;
        }
        workgroupBarrier();

        var reduceSize = min(cols, wg);
        for (var currSize = reduceSize >> 1;  currSize > 0; currSize = reduceSize >> 1) {
          reduceSize = currSize + (reduceSize & 1);
          if (lindex < currSize) {
            threadShared[lindex] = max(threadShared[lindex], threadShared[lindex + reduceSize]);
          }
          workgroupBarrier();
        }
        if (lindex == 0) {
          rowMaxShared = ${S}(${x("threadShared[0]",g)});
        }
        workgroupBarrier();

        // find the rows sum
        var threadSum = ${S}(0.0);
        for (var col = lindex; col < cols; col += wg) {
          let subExp = exp(getValue(row, col, row_stride) - rowMaxShared);
          threadSum += subExp;
        }
        threadShared[lindex] = threadSum;
        workgroupBarrier();

        for (var currSize = wg >> 1;  currSize > 0; currSize = currSize >> 1) {
          if (lindex < currSize) {
            threadShared[lindex] = threadShared[lindex] + threadShared[lindex + currSize];
          }
          workgroupBarrier();
        }
        if (lindex == 0) {
          rowSumShared = ${S}(${mt("threadShared[0]",g)});
        }
        workgroupBarrier();

        // calculate final value for each element in the row
        for (var col = lindex; col < cols; col += wg) {
          let value = exp(getValue(row, col, row_stride) - rowMaxShared) / rowSumShared;
          setValue(row, col, row_stride, value);
        }
      }`,E=e.compute({name:"Softmax",shaderCache:{hint:`${g};${b}`,inputDependencies:["type"]},getRunData:()=>({outputs:[{dims:c,dataType:d.dataType}],dispatchGroup:{x:m},programUniforms:[{type:6,data:_}]}),getShaderSource:T},{inputs:[d],outputs:[u?-1:0]})[0];u&&e.compute(Me(E,l),{inputs:[E]})},cf=(e,t)=>{Dl(e.inputs),Pl(e,t)},ff=e=>pe({axis:e.axis})}),sa,Ul,ql,Wl,hf,hg=P(()=>{ee(),ae(),ne(),sa=e=>Array.from(e.getBigInt64Array(),Number),Ul=e=>{if(!e||e.length!==2)throw new Error("Tile requires 2 inputs.");if(e[0].dataType!==1&&e[0].dataType!==10&&e[0].dataType!==6&&e[0].dataType!==12)throw new Error("Tile only support float, float16, int32, and uint32 data types");if(e[1].dataType!==7)throw new Error("Tile `repeats` input should be of int64 data type");if(e[1].dims.length!==1)throw new Error("Tile `repeats` input should be 1-D");if(sa(e[1]).length!==e[0].dims.length)throw new Error("Tile `repeats` input should have same number of elements as rank of input data tensor")},ql=(e,t)=>{let r=[];for(let a=0;a<e.length;++a)r.push(e[a]*t[a]);return r},Wl=(e,t)=>{let r=e[0].dims,a=t??sa(e[1]),n=ql(r,a),i=O.size(n),s=e[0].dataType,u=R("input",s,r.length),d=H("output",s,n.length),l=c=>`
      const inputShape = ${u.indices(...r)};
      ${c.registerUniform("output_size","u32").declareVariables(u,d)}
      ${c.mainStart()}
      ${c.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.output_size")}
      let output_indices = ${d.offsetToIndices("global_idx")};
      var input_indices: ${u.type.indices};
      for (var i = 0; i < ${r.length}; i++) {
        let input_dim_i = ${u.indicesGet("uniforms.input_shape","i")};
        let input_dim_value = ${d.indicesGet("output_indices","i")}  % input_dim_i;

        ${u.indicesSet("input_indices","i","input_dim_value")}
      }
      ${d.setByOffset("global_idx",u.getByIndices("input_indices"))}
    }`;return{name:"Tile",shaderCache:{hint:`${a}`,inputDependencies:["rank"]},getRunData:()=>({outputs:[{dims:n,dataType:e[0].dataType}],dispatchGroup:{x:Math.ceil(i/64)},programUniforms:[{type:12,data:i},...Q(e[0].dims,n)]}),getShaderSource:l}},hf=e=>{Ul(e.inputs),e.compute(Wl(e.inputs),{inputs:[0]})}}),Vl,Ll,mf,mg=P(()=>{ee(),ae(),ne(),Vl=(e,t,r,a,n)=>{let i=H("output_data",n,r.length,4),s=R("a_data",t[1].dataType,t[1].dims.length,4),u=R("b_data",t[2].dataType,t[2].dims.length,4),d=R("c_data",t[0].dataType,t[0].dims.length,4),l,c=(f,m,g)=>`select(${m}, ${f}, ${g})`;if(!a)l=i.setByOffset("global_idx",c(s.getByOffset("global_idx"),u.getByOffset("global_idx"),d.getByOffset("global_idx")));else{let f=(m,g,_="")=>{let b=`a_data[index_a${g}][component_a${g}]`,x=`b_data[index_b${g}][component_b${g}]`,$=`bool(c_data[index_c${g}] & (0xffu << (component_c${g} * 8)))`;return`
            let output_indices${g} = ${i.offsetToIndices(`global_idx * 4u + ${g}u`)};
            let offset_a${g} = ${s.broadcastedIndicesToOffset(`output_indices${g}`,i)};
            let offset_b${g} = ${u.broadcastedIndicesToOffset(`output_indices${g}`,i)};
            let offset_c${g} = ${d.broadcastedIndicesToOffset(`output_indices${g}`,i)};
            let index_a${g} = offset_a${g} / 4u;
            let index_b${g} = offset_b${g} / 4u;
            let index_c${g} = offset_c${g} / 4u;
            let component_a${g} = offset_a${g} % 4u;
            let component_b${g} = offset_b${g} % 4u;
            let component_c${g} = offset_c${g} % 4u;
            ${m}[${g}] = ${_}(${c(b,x,$)});
          `};n===9?l=`
            var data = vec4<u32>(0);
            ${f("data",0,"u32")}
            ${f("data",1,"u32")}
            ${f("data",2,"u32")}
            ${f("data",3,"u32")}
            output_data[global_idx] = dot(vec4<u32>(0x1, 0x100, 0x10000, 0x1000000), vec4<u32>(data));`:l=`
            ${f("output_data[global_idx]",0)}
            ${f("output_data[global_idx]",1)}
            ${f("output_data[global_idx]",2)}
            ${f("output_data[global_idx]",3)}
          `}return`
        ${e.registerUniform("vec_size","u32").declareVariables(d,s,u,i)}
        ${e.mainStart()}
        ${e.guardAgainstOutOfBoundsWorkgroupSizes("uniforms.vec_size")}
        ${l}
      }`},Ll=e=>{let t=e[1].dims,r=e[2].dims,a=e[0].dims,n=e[1].dataType,i=!(O.areEqual(t,r)&&O.areEqual(r,a)),s=t,u=O.size(t);if(i){let l=Pt.calcShape(Pt.calcShape(t,r,!1),a,!1);if(!l)throw new Error("Can't perform where op on the given tensors");s=l,u=O.size(s)}let d=Math.ceil(u/4);return{name:"Where",shaderCache:{inputDependencies:["rank","rank","rank"]},getShaderSource:l=>Vl(l,e,s,i,n),getRunData:()=>({outputs:[{dims:s,dataType:n}],dispatchGroup:{x:Math.ceil(u/64/4)},programUniforms:[{type:12,data:d},...Q(a,t,r,s)]})}},mf=e=>{e.compute(Ll(e.inputs))}}),gf,gg=P(()=>{Cm(),La(),Om(),Am(),Bm(),Rm(),Nm(),qm(),Vm(),Lm(),Gm(),Hm(),Fm(),jm(),Km(),Zm(),Qm(),Xm(),Ym(),Jm(),eg(),tg(),rg(),ig(),ag(),Rc(),ng(),sg(),og(),ug(),lg(),Va(),dg(),Uc(),pg(),cg(),fg(),Dc(),hg(),gt(),Ga(),mg(),gf=new Map([["Abs",[up]],["Acos",[lp]],["Acosh",[dp]],["Add",[Gp]],["ArgMax",[ap,ya]],["ArgMin",[ip,ya]],["Asin",[pp]],["Asinh",[cp]],["Atan",[fp]],["Atanh",[hp]],["Attention",[np]],["AveragePool",[Kc,jc]],["BatchNormalization",[sp]],["BiasAdd",[op]],["BiasSplitGelu",[Lp]],["Cast",[gp,mp]],["Ceil",[yp]],["Clip",[_p]],["Concat",[ec,tc]],["Conv",[ka,xa]],["ConvTranspose",[pc,dc]],["Cos",[bp]],["Cosh",[wp]],["CumSum",[cc,fc]],["DepthToSpace",[hc,mc]],["DequantizeLinear",[tf,rf]],["Div",[Hp]],["Einsum",[gc,_c]],["Elu",[$p,ir]],["Equal",[Fp]],["Erf",[vp]],["Exp",[xp]],["Expand",[yc]],["FastGelu",[bc]],["Floor",[kp]],["FusedConv",[ka,xa]],["Gather",[$c,wc]],["GatherElements",[Ic,Tc]],["GatherBlockQuantized",[kc,Sc]],["GatherND",[vc,xc]],["Gelu",[Sp]],["Gemm",[zc,Ec]],["GlobalAveragePool",[Qc,Zc]],["GlobalMaxPool",[ef,Jc]],["Greater",[Qp]],["GreaterOrEqual",[Yp]],["GridSample",[Cc,Oc]],["GroupQueryAttention",[qc]],["HardSigmoid",[Bp,Ap]],["InstanceNormalization",[Wc]],["LayerNormalization",[Vc]],["LeakyRelu",[Tp,ir]],["Less",[Xp]],["LessOrEqual",[Jp]],["Log",[Wp]],["MatMul",[Lc]],["MatMulNBits",[Gc,Hc]],["MaxPool",[Xc,Yc]],["Mul",[jp]],["MultiHeadAttention",[Bc,Ac]],["Neg",[Ep]],["Not",[Ip]],["Pad",[Fc]],["Pow",[Kp]],["QuickGelu",[Vp,ir]],["Range",[af]],["Reciprocal",[zp]],["ReduceMin",[Yd]],["ReduceMean",[jd]],["ReduceMax",[Xd]],["ReduceSum",[ep]],["ReduceProd",[Jd]],["ReduceL1",[Kd]],["ReduceL2",[Zd]],["ReduceLogSum",[rp]],["ReduceLogSumExp",[Qd]],["ReduceSumSquare",[tp]],["Relu",[Cp]],["Resize",[of,uf]],["RotaryEmbedding",[Pc]],["ScatterND",[sf,nf]],["Sigmoid",[Op]],["Sin",[Rp]],["Sinh",[Np]],["Slice",[df,pf]],["SkipLayerNormalization",[lf]],["Split",[Nc,Mc]],["Sqrt",[Mp]],["Softmax",[cf,ff]],["Sub",[Zp]],["Tan",[Dp]],["Tanh",[Pp]],["ThresholdedRelu",[qp,ir]],["Tile",[hf]],["Transpose",[Nd,Md]],["Where",[mf]]])}),_f,_g=P(()=>{je(),nt(),ne(),_f=class{constructor(e){this.backend=e,this.repo=new Map,this.attributesBound=!1}getArtifact(e){return this.repo.get(e)}setArtifact(e,t){this.repo.set(e,t)}run(e,t,r,a,n){Je(e.programInfo.name);let i=this.backend.device,s=this.backend.getComputePassEncoder();this.backend.writeTimestamp(this.backend.pendingDispatchNumber*2);let u=[];for(let l of t)u.push({binding:u.length,resource:{buffer:l.buffer}});for(let l of r)u.push({binding:u.length,resource:{buffer:l.buffer}});n&&u.push({binding:u.length,resource:n});let d=i.createBindGroup({layout:e.computePipeline.getBindGroupLayout(0),entries:u,label:e.programInfo.name});if(this.backend.sessionStatus==="capturing"){let l={kernelId:this.backend.currentKernelId,computePipeline:e.computePipeline,bindGroup:d,dispatchGroup:a};this.backend.capturedCommandList.get(this.backend.currentSessionId).push(l)}s.setPipeline(e.computePipeline),s.setBindGroup(0,d),s.dispatchWorkgroups(...a),this.backend.writeTimestamp(this.backend.pendingDispatchNumber*2+1),this.backend.pendingDispatchNumber++,(this.backend.pendingDispatchNumber>=this.backend.maxDispatchNumber||this.backend.queryType==="at-passes")&&this.backend.endComputePass(),this.backend.pendingDispatchNumber>=this.backend.maxDispatchNumber&&this.backend.flush(),Fe(e.programInfo.name)}dispose(){}build(e,t){Je(e.name);let r=this.backend.device,a=[];[{feature:"shader-f16",extension:"f16"},{feature:"subgroups",extension:"subgroups"}].forEach(l=>{r.features.has(l.feature)&&a.push(`enable ${l.extension};`)});let n=Rd(t,this.backend.device.limits),i=e.getShaderSource(n),s=`${a.join(`
`)}
${n.additionalImplementations}
${i}`,u=r.createShaderModule({code:s,label:e.name});ue("verbose",()=>`[WebGPU] ${e.name} shader code: ${s}`);let d=r.createComputePipeline({compute:{module:u,entryPoint:"main"},layout:"auto",label:e.name});return Fe(e.name),{programInfo:e,computePipeline:d,uniformVariablesInfo:n.variablesInfo}}normalizeDispatchGroupSize(e){let t=typeof e=="number"?e:e.x,r=typeof e=="number"?1:e.y||1,a=typeof e=="number"?1:e.z||1,n=this.backend.device.limits.maxComputeWorkgroupsPerDimension;if(t<=n&&r<=n&&a<=n)return[t,r,a];let i=t*r*a,s=Math.ceil(Math.sqrt(i));if(s>n){if(s=Math.ceil(Math.cbrt(i)),s>n)throw new Error("Total dispatch size exceeds WebGPU maximum.");return[s,s,s]}else return[s,s,1]}}}),yf={};qt(yf,{WebGpuBackend:()=>bf});var Gl,Hl,Fl,bf,yg=P(()=>{je(),ee(),nt(),zd(),Em(),gg(),_g(),Gl=(e,t)=>{if(t.length!==e.length)throw new Error(`inputDependencies length ${t.length} is not equal to inputTensors length ${e.length}.`);let r=[];for(let a=0;a<e.length;++a){let n=e[a].dataType;switch(t[a]){case"none":{r.push("");break}case"type":{r.push(`${n}`);break}case"rank":{let i=e[a].dims.length;r.push(`${n};${i}`);break}case"dims":{let i=e[a].dims.join(",");r.push(`${n};${i}`);break}default:throw new Error(`unsupported input dependency: ${t[a]}`)}}return r.join("|")},Hl=(e,t,r)=>{var n,i;let a=e.name;return(n=e.shaderCache)!=null&&n.hint&&(a+="["+e.shaderCache.hint+"]"),a+=":"+r+`:${Gl(t,((i=e.shaderCache)==null?void 0:i.inputDependencies)??new Array(t.length).fill("dims"))}`,a},Fl=class{constructor(e){e&&(this.architecture=e.architecture,this.vendor=e.vendor)}isArchitecture(e){return this.architecture===e}isVendor(e){return this.vendor===e}},bf=class{constructor(){this.currentSessionId=null,this.currentKernelId=null,this.commandEncoder=null,this.computePassEncoder=null,this.maxDispatchNumber=16,this.pendingDispatchNumber=0,this.pendingKernels=[],this.pendingQueries=new Map,this.sessionStatus="default",this.capturedCommandList=new Map,this.capturedPendingKernels=new Map,this.sessionExternalDataMapping=new Map}get currentKernelCustomData(){if(this.currentKernelId===null)throw new Error("currentKernelCustomData(): currentKernelId is null. (should not happen)");let e=this.kernelCustomData.get(this.currentKernelId);return e||(e={},this.kernelCustomData.set(this.currentKernelId,e)),e}async initialize(e,t){this.env=e;let r=[],a={requiredLimits:{maxComputeWorkgroupStorageSize:t.limits.maxComputeWorkgroupStorageSize,maxComputeWorkgroupsPerDimension:t.limits.maxComputeWorkgroupsPerDimension,maxStorageBufferBindingSize:t.limits.maxStorageBufferBindingSize,maxBufferSize:t.limits.maxBufferSize,maxComputeInvocationsPerWorkgroup:t.limits.maxComputeInvocationsPerWorkgroup,maxComputeWorkgroupSizeX:t.limits.maxComputeWorkgroupSizeX,maxComputeWorkgroupSizeY:t.limits.maxComputeWorkgroupSizeY,maxComputeWorkgroupSizeZ:t.limits.maxComputeWorkgroupSizeZ},requiredFeatures:r},n=i=>t.features.has(i)&&r.push(i)&&!0;n("chromium-experimental-timestamp-query-inside-passes")||n("timestamp-query"),n("shader-f16"),n("subgroups"),this.device=await t.requestDevice(a),this.adapterInfo=new Fl(t.info||await t.requestAdapterInfo()),this.gpuDataManager=Ad(this),this.programManager=new _f(this),this.kernels=new Map,this.kernelPersistentData=new Map,this.kernelCustomData=new Map,Pa(e.logLevel,!!e.debug),this.device.onuncapturederror=i=>{i.error instanceof GPUValidationError&&console.error(`An uncaught WebGPU validation error was raised: ${i.error.message}`)},Object.defineProperty(this.env.webgpu,"device",{value:this.device,writable:!1,enumerable:!0,configurable:!1}),Object.defineProperty(this.env.webgpu,"adapter",{value:t,writable:!1,enumerable:!0,configurable:!1}),this.setQueryType()}dispose(){typeof this.querySet<"u"&&this.querySet.destroy(),this.gpuDataManager.dispose()}getCommandEncoder(){return this.commandEncoder||(this.commandEncoder=this.device.createCommandEncoder()),this.commandEncoder}getComputePassEncoder(){if(!this.computePassEncoder){let e=this.getCommandEncoder(),t={};this.queryType==="at-passes"&&(t.timestampWrites={querySet:this.querySet,beginningOfPassWriteIndex:this.pendingDispatchNumber*2,endOfPassWriteIndex:this.pendingDispatchNumber*2+1}),this.computePassEncoder=e.beginComputePass(t)}return this.computePassEncoder}endComputePass(){this.computePassEncoder&&(this.computePassEncoder.end(),this.computePassEncoder=null)}flush(){if(!this.commandEncoder)return;Je(),this.endComputePass();let e;this.queryType!=="none"&&(this.commandEncoder.resolveQuerySet(this.querySet,0,this.pendingDispatchNumber*2,this.queryResolveBuffer,0),e=this.device.createBuffer({size:this.pendingDispatchNumber*2*8,usage:GPUBufferUsage.MAP_READ|GPUBufferUsage.COPY_DST}),this.pendingQueries.set(e,this.pendingKernels),this.pendingKernels=[],this.commandEncoder.copyBufferToBuffer(this.queryResolveBuffer,0,e,0,this.pendingDispatchNumber*2*8)),this.device.queue.submit([this.commandEncoder.finish()]),this.gpuDataManager.refreshPendingBuffers(),this.commandEncoder=null,this.pendingDispatchNumber=0,this.queryType!=="none"&&e.mapAsync(GPUMapMode.READ).then(()=>{var a;let t=new BigUint64Array(e.getMappedRange()),r=this.pendingQueries.get(e);for(let n=0;n<t.length/2;n++){let i=r[n],s=i.kernelId,u=this.kernels.get(s),d=u.kernelType,l=u.kernelName,c=i.programName,f=i.inputTensorViews,m=i.outputTensorViews,g=t[n*2],_=t[n*2+1];typeof this.queryTimeBase>"u"&&(this.queryTimeBase=g);let b=Number(g-this.queryTimeBase),x=Number(_-this.queryTimeBase);if(!Number.isSafeInteger(b)||!Number.isSafeInteger(x))throw new RangeError("incorrect timestamp range");if((a=this.env.webgpu.profiling)!=null&&a.ondata)this.env.webgpu.profiling.ondata({version:1,inputsMetadata:f.map($=>({dims:$.dims,dataType:at($.dataType)})),outputsMetadata:m.map($=>({dims:$.dims,dataType:at($.dataType)})),kernelId:s,kernelType:d,kernelName:l,programName:c,startTime:b,endTime:x});else{let $="";f.forEach((S,k)=>{$+=`input[${k}]: [${S.dims}] | ${at(S.dataType)}, `});let w="";m.forEach((S,k)=>{w+=`output[${k}]: [${S.dims}] | ${at(S.dataType)}, `}),console.log(`[profiling] kernel "${s}|${d}|${l}|${c}" ${$}${w}execution time: ${x-b} ns`)}Nr("GPU",`${c}::${g}::${_}`)}e.unmap(),this.pendingQueries.delete(e)}),Fe()}run(e,t,r,a,n,i){Je(e.name);let s=[];for(let w=0;w<t.length;++w){let S=t[w].data;if(S===0)continue;let k=this.gpuDataManager.get(S);if(!k)throw new Error(`no GPU data for input: ${S}`);s.push(k)}let{outputs:u,dispatchGroup:d,programUniforms:l}=e.getRunData(t),c=r.length===0?u.map((w,S)=>S):r;if(c.length!==u.length)throw new Error(`Output size ${c.length} must be equal to ${u.length}.`);let f=[],m=[];for(let w=0;w<u.length;++w){if(!Number.isInteger(c[w])||c[w]<-3||c[w]>=i)throw new Error(`Invalid output index: ${c[w]}`);if(c[w]===-3)continue;let S=c[w]===-1,k=c[w]===-2,T=S||k?n(u[w].dataType,u[w].dims):a(c[w],u[w].dataType,u[w].dims);if(f.push(T),T.data===0)continue;let E=this.gpuDataManager.get(T.data);if(!E)throw new Error(`no GPU data for output: ${T.data}`);if(S&&this.temporaryData.push(E),k){let z=this.kernelPersistentData.get(this.currentKernelId);z||(z=[],this.kernelPersistentData.set(this.currentKernelId,z)),z.push(E)}m.push(E)}if(s.length!==t.length||m.length!==f.length){if(m.length===0)return Fe(e.name),f;throw new Error(`Program ${e.name} has zero-sized tensor(s) in inputs or outputs. This is not supported now.`)}let g;if(l){let w=0,S=[];l.forEach(z=>{let C=typeof z.data=="number"?[z.data]:z.data;if(C.length===0)return;let A=z.type===10?2:4,q,X;z.type===10?(X=C.length>4?16:C.length>2?8:C.length*A,q=C.length>4?16:A*C.length):(X=C.length<=2?C.length*A:16,q=16),w=Math.ceil(w/X)*X,S.push(w);let G=z.type===10?8:4;w+=C.length>4?Math.ceil(C.length/G)*q:C.length*A});let k=16;w=Math.ceil(w/k)*k;let T=new ArrayBuffer(w);l.forEach((z,C)=>{let A=S[C],q=typeof z.data=="number"?[z.data]:z.data;if(z.type===6)new Int32Array(T,A,q.length).set(q);else if(z.type===12)new Uint32Array(T,A,q.length).set(q);else if(z.type===10)new Uint16Array(T,A,q.length).set(q);else if(z.type===1)new Float32Array(T,A,q.length).set(q);else throw new Error(`Unsupported uniform type: ${at(z.type)}`)});let E=this.gpuDataManager.create(w,GPUBufferUsage.COPY_DST|GPUBufferUsage.UNIFORM);this.device.queue.writeBuffer(E.buffer,0,T,0,w),this.gpuDataManager.release(E.id),g={offset:0,size:w,buffer:E.buffer}}let _=this.programManager.normalizeDispatchGroupSize(d),b=_[1]===1&&_[2]===1,x=Hl(e,t,b),$=this.programManager.getArtifact(x);if($||($=this.programManager.build(e,_),this.programManager.setArtifact(x,$),ue("info",()=>`[artifact] key: ${x}, programName: ${e.name}`)),l&&$.uniformVariablesInfo){if(l.length!==$.uniformVariablesInfo.length)throw new Error(`Uniform variables count mismatch: expect ${$.uniformVariablesInfo.length}, got ${l.length} in program "${$.programInfo.name}".`);for(let w=0;w<l.length;w++){let S=l[w],k=S.type,T=typeof S.data=="number"?1:S.data.length,[E,z]=$.uniformVariablesInfo[w];if(k!==E||T!==z)throw new Error(`Uniform variable ${w} mismatch: expect type ${E} with size ${z}, got type ${k} with size ${T} in program "${$.programInfo.name}".`)}}if(ue("info",()=>`[ProgramManager] run "${e.name}" (key=${x}) with ${_[0]}x${_[1]}x${_[2]}`),this.queryType!=="none"||this.sessionStatus==="capturing"){let w={kernelId:this.currentKernelId,programName:$.programInfo.name,inputTensorViews:t,outputTensorViews:f};this.pendingKernels.push(w),this.sessionStatus==="capturing"&&this.capturedPendingKernels.get(this.currentSessionId).push(w)}return this.programManager.run($,s,m,_,g),Fe(e.name),f}upload(e,t){this.gpuDataManager.upload(e,t)}memcpy(e,t){this.gpuDataManager.memcpy(e,t)}async download(e,t){await this.gpuDataManager.download(e,t)}alloc(e){return this.gpuDataManager.create(e).id}free(e){return this.gpuDataManager.release(e)}createKernel(e,t,r,a){let n=gf.get(e);if(!n)throw new Error(`kernel not implemented: ${e}`);let i={kernelType:e,kernelName:a,kernelEntry:n[0],attributes:[n[1],r]};this.kernels.set(t,i)}releaseKernel(e){let t=this.kernelPersistentData.get(e);if(t){for(let r of t)this.gpuDataManager.release(r.id);this.kernelPersistentData.delete(e)}this.kernelCustomData.delete(e),this.kernels.delete(e)}computeKernel(e,t,r){let a=this.kernels.get(e);if(!a)throw new Error(`kernel not created: ${e}`);let n=a.kernelType,i=a.kernelName,s=a.kernelEntry,u=a.attributes;if(this.currentKernelId!==null)throw new Error(`kernel "[${n}] ${i}" is not allowed to be called recursively`);this.currentKernelId=e,u[0]&&(u[1]=u[0](u[1]),u[0]=void 0),ue("info",()=>`[WebGPU] Start to run kernel "[${n}] ${i}"...`);let d=this.env.debug;this.temporaryData=[];try{return d&&this.device.pushErrorScope("validation"),s(t,u[1]),0}catch(l){return r.push(Promise.resolve(`[WebGPU] Kernel "[${n}] ${i}" failed. ${l}`)),1}finally{d&&r.push(this.device.popErrorScope().then(l=>l?`GPU validation error for kernel "[${n}] ${i}": ${l.message}`:null));for(let l of this.temporaryData)this.gpuDataManager.release(l.id);this.temporaryData=[],this.currentKernelId=null}}registerBuffer(e,t,r,a){let n=this.sessionExternalDataMapping.get(e);n||(n=new Map,this.sessionExternalDataMapping.set(e,n));let i=n.get(t),s=this.gpuDataManager.registerExternalBuffer(r,a,i);return n.set(t,[s,r]),s}unregisterBuffers(e){let t=this.sessionExternalDataMapping.get(e);t&&(t.forEach(r=>this.gpuDataManager.unregisterExternalBuffer(r[0])),this.sessionExternalDataMapping.delete(e))}getBuffer(e){let t=this.gpuDataManager.get(e);if(!t)throw new Error(`no GPU data for buffer: ${e}`);return t.buffer}createDownloader(e,t,r){return async()=>{let a=await ma(this,e,t);return Ua(a.buffer,r)}}writeTimestamp(e){this.queryType==="inside-passes"&&this.computePassEncoder.writeTimestamp(this.querySet,e)}setQueryType(){var e;this.queryType="none",(((e=this.env.webgpu.profiling)==null?void 0:e.mode)==="default"||(typeof this.env.trace>"u"?this.env.wasm.trace:this.env.trace))&&(this.device.features.has("chromium-experimental-timestamp-query-inside-passes")?this.queryType="inside-passes":this.device.features.has("timestamp-query")&&(this.queryType="at-passes"),this.queryType!=="none"&&typeof this.querySet>"u"&&(this.querySet=this.device.createQuerySet({type:"timestamp",count:this.maxDispatchNumber*2}),this.queryResolveBuffer=this.device.createBuffer({size:this.maxDispatchNumber*2*8,usage:GPUBufferUsage.COPY_SRC|GPUBufferUsage.QUERY_RESOLVE})))}captureBegin(){ue("info","captureBegin"),this.capturedCommandList.get(this.currentSessionId)||this.capturedCommandList.set(this.currentSessionId,[]),this.capturedPendingKernels.get(this.currentSessionId)||this.capturedPendingKernels.set(this.currentSessionId,[]),this.flush(),this.sessionStatus="capturing"}captureEnd(){ue("info","captureEnd"),this.flush(),this.sessionStatus="default"}replay(){ue("info","replay"),this.sessionStatus="replaying";let e=this.capturedCommandList.get(this.currentSessionId),t=this.capturedPendingKernels.get(this.currentSessionId),r=e.length;this.pendingKernels=[];for(let a=0;a<r;a++){let n=this.getComputePassEncoder(),i=e[a];this.writeTimestamp(this.pendingDispatchNumber*2),n.setPipeline(i.computePipeline),n.setBindGroup(0,i.bindGroup),n.dispatchWorkgroups(...i.dispatchGroup),this.writeTimestamp(this.pendingDispatchNumber*2+1),this.pendingDispatchNumber++,this.queryType!=="none"&&this.pendingKernels.push(t[a]),(this.pendingDispatchNumber>=this.maxDispatchNumber||this.queryType==="at-passes")&&this.endComputePass(),this.pendingDispatchNumber>=this.maxDispatchNumber&&this.flush()}this.flush(),this.sessionStatus="default"}onCreateSession(){this.gpuDataManager.onCreateSession()}onReleaseSession(e){this.unregisterBuffers(e),this.capturedCommandList.has(e)&&this.capturedCommandList.delete(e),this.capturedPendingKernels.has(e)&&this.capturedPendingKernels.delete(e),this.gpuDataManager.onReleaseSession(e)}onRunStart(e){this.currentSessionId=e,this.setQueryType()}}}),wf={};qt(wf,{init:()=>$f});var Cr,jl,$f,bg=P(()=>{ee(),nt(),ae(),Im(),Cr=class vf{constructor(t,r,a,n){this.module=t,this.dataType=r,this.data=a,this.dims=n}getFloat32Array(){if(this.dataType!==1)throw new Error("Invalid data type");let t=O.size(this.dims);return t===0?new Float32Array:new Float32Array(this.module.HEAP8.buffer,this.data,t)}getBigInt64Array(){if(this.dataType!==7)throw new Error("Invalid data type");let t=O.size(this.dims);return t===0?new BigInt64Array:new BigInt64Array(this.module.HEAP8.buffer,this.data,t)}getInt32Array(){if(this.dataType!==6)throw new Error("Invalid data type");let t=O.size(this.dims);return t===0?new Int32Array:new Int32Array(this.module.HEAP8.buffer,this.data,t)}getUint16Array(){if(this.dataType!==10&&this.dataType!==4)throw new Error("Invalid data type");let t=O.size(this.dims);return t===0?new Uint16Array:new Uint16Array(this.module.HEAP8.buffer,this.data,t)}reshape(t){if(O.size(t)!==O.size(this.dims))throw new Error("Invalid new shape");return new vf(this.module,this.dataType,this.data,t)}},jl=class{constructor(e,t,r){this.module=e,this.backend=t,this.customDataOffset=0,this.customDataSize=0,this.adapterInfo=t.adapterInfo;let a=e.PTR_SIZE,n=r/e.PTR_SIZE,i=a===4?"i32":"i64";this.opKernelContext=Number(e.getValue(a*n++,i));let s=Number(e.getValue(a*n++,i));this.outputCount=Number(e.getValue(a*n++,i)),this.customDataOffset=Number(e.getValue(a*n++,"*")),this.customDataSize=Number(e.getValue(a*n++,i));let u=[];for(let d=0;d<s;d++){let l=Number(e.getValue(a*n++,i)),c=Number(e.getValue(a*n++,"*")),f=Number(e.getValue(a*n++,i)),m=[];for(let g=0;g<f;g++)m.push(Number(e.getValue(a*n++,i)));u.push(new Cr(e,l,c,m))}this.inputs=u}get kernelCustomData(){return this.backend.currentKernelCustomData}get customDataBuffer(){return this.module.HEAPU8.subarray(this.customDataOffset,this.customDataOffset+this.customDataSize)}compute(e,t){var s;let r=((s=t==null?void 0:t.inputs)==null?void 0:s.map(u=>typeof u=="number"?this.inputs[u]:u))??this.inputs,a=(t==null?void 0:t.outputs)??[],n=(u,d,l)=>new Cr(this.module,d,this.output(u,l),l),i=(u,d)=>{let l=Tt(u,d);if(!l)throw new Error(`Unsupported data type: ${u}`);let c=l>0?this.backend.gpuDataManager.create(l).id:0;return new Cr(this.module,u,c,d)};return this.backend.run(e,r,a,n,i,this.outputCount)}output(e,t){let r=this.module.stackSave();try{let a=this.module.PTR_SIZE,n=a===4?"i32":"i64",i=this.module.stackAlloc((1+t.length)*a);this.module.setValue(i,t.length,n);for(let s=0;s<t.length;s++)this.module.setValue(i+a*(s+1),t[s],n);return this.module._JsepOutput(this.opKernelContext,e,i)}catch(a){throw new Error(`Failed to generate kernel's output[${e}] with dims [${t}]. If you are running with pre-allocated output, please make sure the output type/dims are correct. Error: ${a}`)}finally{this.module.stackRestore(r)}}},$f=async(e,t,r,a)=>{let n=t.jsepInit;if(!n)throw new Error("Failed to initialize JSEP. The WebAssembly module is not built with JSEP support.");if(e==="webgpu"){let i=(yg(),or(yf)).WebGpuBackend,s=new i;await s.initialize(r,a),n("webgpu",[s,u=>s.alloc(Number(u)),u=>s.free(u),(u,d,l,c=!1)=>{if(c)ue("verbose",()=>`[WebGPU] jsepCopyGpuToGpu: src=${Number(u)}, dst=${Number(d)}, size=${Number(l)}`),s.memcpy(Number(u),Number(d));else{ue("verbose",()=>`[WebGPU] jsepCopyCpuToGpu: dataOffset=${Number(u)}, gpuDataId=${Number(d)}, size=${Number(l)}`);let f=t.HEAPU8.subarray(Number(u>>>0),Number(u>>>0)+Number(l));s.upload(Number(d),f)}},async(u,d,l)=>{ue("verbose",()=>`[WebGPU] jsepCopyGpuToCpu: gpuDataId=${u}, dataOffset=${d}, size=${l}`),await s.download(Number(u),()=>t.HEAPU8.subarray(Number(d)>>>0,Number(d+l)>>>0))},(u,d,l)=>s.createKernel(u,Number(d),l,t.UTF8ToString(t._JsepGetNodeName(Number(d)))),u=>s.releaseKernel(u),(u,d,l,c)=>{ue("verbose",()=>`[WebGPU] jsepRun: sessionHandle=${l}, kernel=${u}, contextDataOffset=${d}`);let f=new jl(t,s,Number(d));return s.computeKernel(Number(u),f,c)},()=>s.captureBegin(),()=>s.captureEnd(),()=>s.replay()])}else{let i=new Od(r);n("webnn",[i,()=>i.reserveTensorId(),s=>i.releaseTensorId(s),async(s,u,d,l,c)=>i.ensureTensor(s,u,d,l,c),(s,u)=>{i.uploadTensor(s,u)},async(s,u)=>i.downloadTensor(s,u)])}}}),Kl,Qa,Xa,ft,Zl,oa,Vr,Ya,Ja,ua,en,tn,rn,xf=P(()=>{km(),Sm(),ee(),Ct(),Ra(),Sd(),Kl=(e,t)=>{ge()._OrtInit(e,t)!==0&&he("Can't initialize onnxruntime.")},Qa=async e=>{Kl(e.wasm.numThreads,Dr(e.logLevel))},Xa=async(e,t)=>{var r,a;(a=(r=ge()).asyncInit)==null||a.call(r);{let n=(bg(),or(wf)).init;if(t==="webgpu"){if(typeof navigator>"u"||!navigator.gpu)throw new Error("WebGPU is not supported in current environment");let i=e.webgpu.adapter;if(i){if(typeof i.limits!="object"||typeof i.features!="object"||typeof i.requestDevice!="function")throw new Error("Invalid GPU adapter set in `env.webgpu.adapter`. It must be a GPUAdapter object.")}else{let s=e.webgpu.powerPreference;if(s!==void 0&&s!=="low-power"&&s!=="high-performance")throw new Error(`Invalid powerPreference setting: "${s}"`);let u=e.webgpu.forceFallbackAdapter;if(u!==void 0&&typeof u!="boolean")throw new Error(`Invalid forceFallbackAdapter setting: "${u}"`);if(i=await navigator.gpu.requestAdapter({powerPreference:s,forceFallbackAdapter:u}),!i)throw new Error('Failed to get GPU adapter. You may need to enable flag "--enable-unsafe-webgpu" if you are using Chrome.')}await n("webgpu",ge(),e,i)}if(t==="webnn"){if(typeof navigator>"u"||!navigator.ml)throw new Error("WebNN is not supported in current environment");await n("webnn",ge(),e)}}},ft=new Map,Zl=e=>{let t=ge(),r=t.stackSave();try{let a=t.PTR_SIZE,n=t.stackAlloc(2*a);t._OrtGetInputOutputCount(e,n,n+a)!==0&&he("Can't get session input/output count.");let i=a===4?"i32":"i64";return[Number(t.getValue(n,i)),Number(t.getValue(n+a,i))]}finally{t.stackRestore(r)}},oa=(e,t)=>{let r=ge(),a=r.stackSave(),n=0;try{let i=r.PTR_SIZE,s=r.stackAlloc(2*i);r._OrtGetInputOutputMetadata(e,t,s,s+i)!==0&&he("Can't get session input/output metadata.");let u=Number(r.getValue(s,"*"));n=Number(r.getValue(s+i,"*"));let d=r.HEAP32[n/4];if(d===0)return[u,0];let l=r.HEAPU32[n/4+1],c=[];for(let f=0;f<l;f++){let m=Number(r.getValue(n+8+f*i,"*"));c.push(m!==0?r.UTF8ToString(m):Number(r.getValue(n+8+(f+l)*i,"*")))}return[u,d,c]}finally{r.stackRestore(a),n!==0&&r._OrtFree(n)}},Vr=e=>{let t=ge(),r=t._malloc(e.byteLength);if(r===0)throw new Error(`Can't create a session. failed to allocate a buffer of size ${e.byteLength}.`);return t.HEAPU8.set(e,r),[r,e.byteLength]},Ya=async(e,t)=>{var f,m,g,_;let r,a,n=ge();Array.isArray(e)?[r,a]=e:e.buffer===n.HEAPU8.buffer?[r,a]=[e.byteOffset,e.byteLength]:[r,a]=Vr(e);let i=0,s=0,u=0,d=[],l=[],c=[];try{if([s,d]=await kd(t),(t==null?void 0:t.externalData)&&n.mountExternalData){let C=[];for(let A of t.externalData){let q=typeof A=="string"?A:A.path;C.push(Da(typeof A=="string"?A:A.data).then(X=>{n.mountExternalData(q,X)}))}await Promise.all(C)}for(let C of(t==null?void 0:t.executionProviders)??[])if((typeof C=="string"?C:C.name)==="webnn"){if(n.shouldTransferToMLTensor=!1,typeof C!="string"){let A=C,q=A==null?void 0:A.context,X=A==null?void 0:A.gpuDevice,G=A==null?void 0:A.deviceType,Z=A==null?void 0:A.powerPreference;q?n.currentContext=q:X?n.currentContext=await n.webnnCreateMLContext(X):n.currentContext=await n.webnnCreateMLContext({deviceType:G,powerPreference:Z})}else n.currentContext=await n.webnnCreateMLContext();break}i=await n._OrtCreateSession(r,a,s),(f=n.webgpuOnCreateSession)==null||f.call(n,i),i===0&&he("Can't create a session."),(m=n.jsepOnCreateSession)==null||m.call(n),n.currentContext&&(n.webnnRegisterMLContext(i,n.currentContext),n.currentContext=void 0,n.shouldTransferToMLTensor=!0);let[b,x]=Zl(i),$=!!(t!=null&&t.enableGraphCapture),w=[],S=[],k=[],T=[],E=[];for(let C=0;C<b;C++){let[A,q,X]=oa(i,C);A===0&&he("Can't get an input name."),l.push(A);let G=n.UTF8ToString(A);w.push(G),k.push(q===0?{name:G,isTensor:!1}:{name:G,isTensor:!0,type:at(q),shape:X})}for(let C=0;C<x;C++){let[A,q,X]=oa(i,C+b);A===0&&he("Can't get an output name."),c.push(A);let G=n.UTF8ToString(A);S.push(G),T.push(q===0?{name:G,isTensor:!1}:{name:G,isTensor:!0,type:at(q),shape:X});{if($&&(t==null?void 0:t.preferredOutputLocation)===void 0){E.push("gpu-buffer");continue}let Z=typeof(t==null?void 0:t.preferredOutputLocation)=="string"?t.preferredOutputLocation:((g=t==null?void 0:t.preferredOutputLocation)==null?void 0:g[G])??"cpu",oe=n.webnnIsGraphOutput;if(Z==="cpu"&&oe&&oe(i,G)){E.push("ml-tensor-cpu-output");continue}if(Z!=="cpu"&&Z!=="cpu-pinned"&&Z!=="gpu-buffer"&&Z!=="ml-tensor")throw new Error(`Not supported preferred output location: ${Z}.`);if($&&Z!=="gpu-buffer")throw new Error(`Not supported preferred output location: ${Z}. Only 'gpu-buffer' location is supported when enableGraphCapture is true.`);E.push(Z)}}let z=null;return E.some(C=>C==="gpu-buffer"||C==="ml-tensor"||C==="ml-tensor-cpu-output")&&(u=n._OrtCreateBinding(i),u===0&&he("Can't create IO binding."),z={handle:u,outputPreferredLocations:E,outputPreferredLocationsEncoded:E.map(C=>C==="ml-tensor-cpu-output"?"ml-tensor":C).map(C=>fa(C))}),ft.set(i,[i,l,c,z,$,!1]),[i,w,S,k,T]}catch(b){throw l.forEach(x=>n._OrtFree(x)),c.forEach(x=>n._OrtFree(x)),u!==0&&n._OrtReleaseBinding(u)!==0&&he("Can't release IO binding."),i!==0&&n._OrtReleaseSession(i)!==0&&he("Can't release session."),b}finally{n._free(r),s!==0&&n._OrtReleaseSessionOptions(s)!==0&&he("Can't release session options."),d.forEach(b=>n._free(b)),(_=n.unmountExternalData)==null||_.call(n)}},Ja=e=>{var d,l,c;let t=ge(),r=ft.get(e);if(!r)throw new Error(`cannot release session. invalid session id: ${e}`);let[a,n,i,s,u]=r;s&&(u&&t._OrtClearBoundOutputs(s.handle)!==0&&he("Can't clear bound outputs."),t._OrtReleaseBinding(s.handle)!==0&&he("Can't release IO binding.")),(d=t.jsepOnReleaseSession)==null||d.call(t,e),(l=t.webnnOnReleaseSession)==null||l.call(t,e),(c=t.webgpuOnReleaseSession)==null||c.call(t,e),n.forEach(f=>t._OrtFree(f)),i.forEach(f=>t._OrtFree(f)),t._OrtReleaseSession(a)!==0&&he("Can't release session."),ft.delete(e)},ua=async(e,t,r,a,n,i,s=!1)=>{if(!e){t.push(0);return}let u=ge(),d=u.PTR_SIZE,l=e[0],c=e[1],f=e[3],m=f,g,_;if(l==="string"&&(f==="gpu-buffer"||f==="ml-tensor"))throw new Error("String tensor is not supported on GPU.");if(s&&f!=="gpu-buffer")throw new Error(`External buffer must be provided for input/output index ${i} when enableGraphCapture is true.`);if(f==="gpu-buffer"){let $=e[2].gpuBuffer;_=Tt(St(l),c);{let w=u.jsepRegisterBuffer;if(!w)throw new Error('Tensor location "gpu-buffer" is not supported without using WebGPU.');g=w(a,i,$,_)}}else if(f==="ml-tensor"){let $=e[2].mlTensor;_=Tt(St(l),c);let w=u.webnnRegisterMLTensor;if(!w)throw new Error('Tensor location "ml-tensor" is not supported without using WebNN.');g=w(a,$,St(l),c)}else{let $=e[2];if(Array.isArray($)){_=d*$.length,g=u._malloc(_),r.push(g);for(let w=0;w<$.length;w++){if(typeof $[w]!="string")throw new TypeError(`tensor data at index ${w} is not a string`);u.setValue(g+w*d,He($[w],r),"*")}}else{let w=u.webnnIsGraphInput,S=u.webnnIsGraphOutput;if(l!=="string"&&w&&S){let k=u.UTF8ToString(n);if(w(a,k)||S(a,k)){let T=St(l);_=Tt(T,c),m="ml-tensor";let E=u.webnnCreateTemporaryTensor,z=u.webnnUploadTensor;if(!E||!z)throw new Error('Tensor location "ml-tensor" is not supported without using WebNN.');let C=await E(a,T,c);z(C,new Uint8Array($.buffer,$.byteOffset,$.byteLength)),g=C}else _=$.byteLength,g=u._malloc(_),r.push(g),u.HEAPU8.set(new Uint8Array($.buffer,$.byteOffset,_),g)}else _=$.byteLength,g=u._malloc(_),r.push(g),u.HEAPU8.set(new Uint8Array($.buffer,$.byteOffset,_),g)}}let b=u.stackSave(),x=u.stackAlloc(4*c.length);try{c.forEach((w,S)=>u.setValue(x+S*d,w,d===4?"i32":"i64"));let $=u._OrtCreateTensor(St(l),g,_,x,c.length,fa(m));$===0&&he(`Can't create tensor for input/output. session=${a}, index=${i}.`),t.push($)}finally{u.stackRestore(b)}},en=async(e,t,r,a,n,i)=>{var X,G,Z,oe;let s=ge(),u=s.PTR_SIZE,d=ft.get(e);if(!d)throw new Error(`cannot run inference. invalid session id: ${e}`);let l=d[0],c=d[1],f=d[2],m=d[3],g=d[4],_=d[5],b=t.length,x=a.length,$=0,w=[],S=[],k=[],T=[],E=s.stackSave(),z=s.stackAlloc(b*u),C=s.stackAlloc(b*u),A=s.stackAlloc(x*u),q=s.stackAlloc(x*u);try{[$,w]=xd(i);for(let F=0;F<b;F++)await ua(r[F],S,T,e,c[t[F]],t[F],g);for(let F=0;F<x;F++)await ua(n[F],k,T,e,f[a[F]],b+a[F],g);for(let F=0;F<b;F++)s.setValue(z+F*u,S[F],"*"),s.setValue(C+F*u,c[t[F]],"*");for(let F=0;F<x;F++)s.setValue(A+F*u,k[F],"*"),s.setValue(q+F*u,f[a[F]],"*");if(m&&!_){let{handle:F,outputPreferredLocations:Y,outputPreferredLocationsEncoded:ye}=m;if(c.length!==b)throw new Error(`input count from feeds (${b}) is expected to be always equal to model's input count (${c.length}).`);for(let N=0;N<b;N++){let U=t[N];await s._OrtBindInput(F,c[U],S[N])!==0&&he(`Can't bind input[${N}] for session=${e}.`)}for(let N=0;N<x;N++){let U=a[N];(X=n[N])!=null&&X[3]?s._OrtBindOutput(F,f[U],k[N],0)!==0&&he(`Can't bind pre-allocated output[${N}] for session=${e}.`):s._OrtBindOutput(F,f[U],0,ye[U])!==0&&he(`Can't bind output[${N}] to ${Y[N]} for session=${e}.`)}ft.set(e,[l,c,f,m,g,!0])}(G=s.jsepOnRunStart)==null||G.call(s,l),(Z=s.webnnOnRunStart)==null||Z.call(s,l);let re;m?re=await s._OrtRunWithBinding(l,m.handle,x,A,$):re=await s._OrtRun(l,C,z,b,q,x,A,$),re!==0&&he("failed to call OrtRun().");let L=[],ie=[];for(let F=0;F<x;F++){let Y=Number(s.getValue(A+F*u,"*"));if(Y===k[F]){L.push(n[F]);continue}let ye=s.stackSave(),N=s.stackAlloc(4*u),U=!1,V,te=0;try{s._OrtGetTensorData(Y,N,N+u,N+2*u,N+3*u)!==0&&he(`Can't access output tensor data on index ${F}.`);let Te=u===4?"i32":"i64",M=Number(s.getValue(N,Te));te=s.getValue(N+u,"*");let ce=s.getValue(N+u*2,"*"),At=Number(s.getValue(N+u*3,Te)),ze=[];for(let fe=0;fe<At;fe++)ze.push(Number(s.getValue(ce+fe*u,Te)));s._OrtFree(ce)!==0&&he("Can't free memory for tensor dims.");let Ue=ze.reduce((fe,we)=>fe*we,1);V=at(M);let et=m==null?void 0:m.outputPreferredLocations[a[F]];if(V==="string"){if(et==="gpu-buffer"||et==="ml-tensor")throw new Error("String tensor is not supported on GPU.");let fe=[];for(let we=0;we<Ue;we++){let Be=s.getValue(te+we*u,"*"),_t=s.getValue(te+(we+1)*u,"*"),yt=we===Ue-1?void 0:_t-Be;fe.push(s.UTF8ToString(Be,yt))}L.push([V,ze,fe,"cpu"])}else if(et==="gpu-buffer"&&Ue>0){let fe=s.jsepGetBuffer;if(!fe)throw new Error('preferredLocation "gpu-buffer" is not supported without using WebGPU.');let we=fe(te),Be=Tt(M,Ue);if(Be===void 0||!Na(V))throw new Error(`Unsupported data type: ${V}`);U=!0,L.push([V,ze,{gpuBuffer:we,download:s.jsepCreateDownloader(we,Be,V),dispose:()=>{s._OrtReleaseTensor(Y)!==0&&he("Can't release tensor.")}},"gpu-buffer"])}else if(et==="ml-tensor"&&Ue>0){let fe=s.webnnEnsureTensor,we=s.webnnIsGraphInputOutputTypeSupported;if(!fe||!we)throw new Error('preferredLocation "ml-tensor" is not supported without using WebNN.');if(Tt(M,Ue)===void 0||!Ma(V))throw new Error(`Unsupported data type: ${V}`);if(!we(e,V,!1))throw new Error(`preferredLocation "ml-tensor" for ${V} output is not supported by current WebNN Context.`);let Be=await fe(e,te,M,ze,!1);U=!0,L.push([V,ze,{mlTensor:Be,download:s.webnnCreateMLTensorDownloader(te,V),dispose:()=>{s.webnnReleaseTensorId(te),s._OrtReleaseTensor(Y)}},"ml-tensor"])}else if(et==="ml-tensor-cpu-output"&&Ue>0){let fe=s.webnnCreateMLTensorDownloader(te,V)(),we=L.length;U=!0,ie.push((async()=>{let Be=[we,await fe];return s.webnnReleaseTensorId(te),s._OrtReleaseTensor(Y),Be})()),L.push([V,ze,[],"cpu"])}else{let fe=Lr(V),we=new fe(Ue);new Uint8Array(we.buffer,we.byteOffset,we.byteLength).set(s.HEAPU8.subarray(te,te+we.byteLength)),L.push([V,ze,we,"cpu"])}}finally{s.stackRestore(ye),V==="string"&&te&&s._free(te),U||s._OrtReleaseTensor(Y)}}m&&!g&&(s._OrtClearBoundOutputs(m.handle)!==0&&he("Can't clear bound outputs."),ft.set(e,[l,c,f,m,g,!1]));for(let[F,Y]of await Promise.all(ie))L[F][2]=Y;return L}finally{(oe=s.webnnOnRunEnd)==null||oe.call(s,l),s.stackRestore(E),S.forEach(re=>s._OrtReleaseTensor(re)),k.forEach(re=>s._OrtReleaseTensor(re)),T.forEach(re=>s._free(re)),$!==0&&s._OrtReleaseRunOptions($),w.forEach(re=>s._free(re))}},tn=e=>{let t=ge(),r=ft.get(e);if(!r)throw new Error("invalid session id");let a=r[0],n=t._OrtEndProfiling(a);n===0&&he("Can't get an profile file name."),t._OrtFree(n)},rn=e=>{let t=[];for(let r of e){let a=r[2];!Array.isArray(a)&&"buffer"in a&&t.push(a.buffer)}return t}}),ht,Ae,Nt,Jt,er,Or,la,Ar,vt,xt,Ql,kf,Sf,Tf,If,Ef,zf,Cf,Of=P(()=>{je(),xf(),Ct(),Aa(),ht=()=>!!_e.wasm.proxy&&typeof document<"u",Nt=!1,Jt=!1,er=!1,Ar=new Map,vt=(e,t)=>{let r=Ar.get(e);r?r.push(t):Ar.set(e,[t])},xt=()=>{if(Nt||!Jt||er||!Ae)throw new Error("worker not ready")},Ql=e=>{switch(e.data.type){case"init-wasm":Nt=!1,e.data.err?(er=!0,la[1](e.data.err)):(Jt=!0,la[0]()),Or&&(URL.revokeObjectURL(Or),Or=void 0);break;case"init-ep":case"copy-from":case"create":case"release":case"run":case"end-profiling":{let t=Ar.get(e.data.type);e.data.err?t.shift()[1](e.data.err):t.shift()[0](e.data.out);break}}},kf=async()=>{if(!Jt){if(Nt)throw new Error("multiple calls to 'initWasm()' detected.");if(er)throw new Error("previous call to 'initWasm()' failed.");if(Nt=!0,ht())return new Promise((e,t)=>{Ae==null||Ae.terminate(),$d().then(([r,a])=>{try{Ae=a,Ae.onerror=i=>t(i),Ae.onmessage=Ql,la=[e,t];let n={type:"init-wasm",in:_e};!n.in.wasm.wasmPaths&&(r||ca)&&(n.in.wasm.wasmPaths={wasm:new URL("/assets/ort-wasm-simd-threaded.jsep-CLPRrI3A.wasm",import.meta.url).href}),Ae.postMessage(n),Or=r}catch(n){t(n)}},t)});try{await Ba(_e.wasm),await Qa(_e),Jt=!0}catch(e){throw er=!0,e}finally{Nt=!1}}},Sf=async e=>{if(ht())return xt(),new Promise((t,r)=>{vt("init-ep",[t,r]);let a={type:"init-ep",in:{epName:e,env:_e}};Ae.postMessage(a)});await Xa(_e,e)},Tf=async e=>ht()?(xt(),new Promise((t,r)=>{vt("copy-from",[t,r]);let a={type:"copy-from",in:{buffer:e}};Ae.postMessage(a,[e.buffer])})):Vr(e),If=async(e,t)=>{if(ht()){if(t!=null&&t.preferredOutputLocation)throw new Error('session option "preferredOutputLocation" is not supported for proxy.');return xt(),new Promise((r,a)=>{vt("create",[r,a]);let n={type:"create",in:{model:e,options:{...t}}},i=[];e instanceof Uint8Array&&i.push(e.buffer),Ae.postMessage(n,i)})}else return Ya(e,t)},Ef=async e=>{if(ht())return xt(),new Promise((t,r)=>{vt("release",[t,r]);let a={type:"release",in:e};Ae.postMessage(a)});Ja(e)},zf=async(e,t,r,a,n,i)=>{if(ht()){if(r.some(s=>s[3]!=="cpu"))throw new Error("input tensor on GPU is not supported for proxy.");if(n.some(s=>s))throw new Error("pre-allocated output tensor is not supported for proxy.");return xt(),new Promise((s,u)=>{vt("run",[s,u]);let d=r,l={type:"run",in:{sessionId:e,inputIndices:t,inputs:d,outputIndices:a,options:i}};Ae.postMessage(l,rn(d))})}else return en(e,t,r,a,n,i)},Cf=async e=>{if(ht())return xt(),new Promise((t,r)=>{vt("end-profiling",[t,r]);let a={type:"end-profiling",in:e};Ae.postMessage(a)});tn(e)}}),da,Xl,Af,wg=P(()=>{je(),Of(),ee(),Oa(),Sd(),da=(e,t)=>{switch(e.location){case"cpu":return[e.type,e.dims,e.data,"cpu"];case"gpu-buffer":return[e.type,e.dims,{gpuBuffer:e.gpuBuffer},"gpu-buffer"];case"ml-tensor":return[e.type,e.dims,{mlTensor:e.mlTensor},"ml-tensor"];default:throw new Error(`invalid data location: ${e.location} for ${t()}`)}},Xl=e=>{switch(e[3]){case"cpu":return new Ye(e[0],e[2],e[1]);case"gpu-buffer":{let t=e[0];if(!Na(t))throw new Error(`not supported data type: ${t} for deserializing GPU tensor`);let{gpuBuffer:r,download:a,dispose:n}=e[2];return Ye.fromGpuBuffer(r,{dataType:t,dims:e[1],download:a,dispose:n})}case"ml-tensor":{let t=e[0];if(!Ma(t))throw new Error(`not supported data type: ${t} for deserializing MLTensor tensor`);let{mlTensor:r,download:a,dispose:n}=e[2];return Ye.fromMLTensor(r,{dataType:t,dims:e[1],download:a,dispose:n})}default:throw new Error(`invalid data location: ${e[3]}`)}},Af=class{async fetchModelAndCopyToWasmMemory(e){return Tf(await Da(e))}async loadModel(e,t){Je();let r;typeof e=="string"?r=await this.fetchModelAndCopyToWasmMemory(e):r=e,[this.sessionId,this.inputNames,this.outputNames,this.inputMetadata,this.outputMetadata]=await If(r,t),Fe()}async dispose(){return Ef(this.sessionId)}async run(e,t,r){Je();let a=[],n=[];Object.entries(e).forEach(f=>{let m=f[0],g=f[1],_=this.inputNames.indexOf(m);if(_===-1)throw new Error(`invalid input '${m}'`);a.push(g),n.push(_)});let i=[],s=[];Object.entries(t).forEach(f=>{let m=f[0],g=f[1],_=this.outputNames.indexOf(m);if(_===-1)throw new Error(`invalid output '${m}'`);i.push(g),s.push(_)});let u=a.map((f,m)=>da(f,()=>`input "${this.inputNames[n[m]]}"`)),d=i.map((f,m)=>f?da(f,()=>`output "${this.outputNames[s[m]]}"`):null),l=await zf(this.sessionId,n,u,s,d,r),c={};for(let f=0;f<l.length;f++)c[this.outputNames[s[f]]]=i[f]??Xl(l[f]);return Fe(),c}startProfiling(){}endProfiling(){Cf(this.sessionId)}}}),Bf={};qt(Bf,{OnnxruntimeWebAssemblyBackend:()=>Ia,initializeFlags:()=>Ta,wasmBackend:()=>Rf});var Ta,Ia,Rf,$g=P(()=>{je(),Of(),wg(),Ta=()=>{(typeof _e.wasm.initTimeout!="number"||_e.wasm.initTimeout<0)&&(_e.wasm.initTimeout=0);let e=_e.wasm.simd;if(typeof e!="boolean"&&e!==void 0&&e!=="fixed"&&e!=="relaxed"&&(console.warn(`Property "env.wasm.simd" is set to unknown value "${e}". Reset it to \`false\` and ignore SIMD feature checking.`),_e.wasm.simd=!1),typeof _e.wasm.proxy!="boolean"&&(_e.wasm.proxy=!1),typeof _e.wasm.trace!="boolean"&&(_e.wasm.trace=!1),typeof _e.wasm.numThreads!="number"||!Number.isInteger(_e.wasm.numThreads)||_e.wasm.numThreads<=0)if(typeof self<"u"&&!self.crossOriginIsolated)_e.wasm.numThreads=1;else{let t=typeof navigator>"u"?sm("node:os").cpus().length:navigator.hardwareConcurrency;_e.wasm.numThreads=Math.min(4,Math.ceil((t||1)/2))}},Ia=class{async init(e){Ta(),await kf(),await Sf(e)}async createInferenceSessionHandler(e,t){let r=new Af;return await r.loadModel(e,t),r}},Rf=new Ia});je();je();je();var vg="1.22.0";{let e=($g(),or(Bf)).wasmBackend;Mt("webgpu",e,5),Mt("webnn",e,5),Mt("cpu",e,10),Mt("wasm",e,10)}Object.defineProperty(_e.versions,"web",{value:vg,enumerable:!0});/**
* @license
* Copyright 2021 Google LLC. All Rights Reserved.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
* =============================================================================
*//**
 * @license
 * Copyright 2020 Google LLC. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =============================================================================
 *//**
 * @license
 * Copyright 2019 Google LLC. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =============================================================================
 */async function xg(){const e=chrome.runtime.getURL("rf_model.onnx"),r=await(await fetch(e)).arrayBuffer();return await Ca.create(r)}let nr=null;const kg=.58,pa={};(async()=>{try{nr=await xg(),console.log("✅ ONNX model loaded")}catch(e){console.error("❌ Failed to load ONNX model",e)}})();function Sg(e){const t=Float32Array.from([e.url_length,e.dot_count,e.subdomain_length,e.entropy]);return new ort.Tensor("float32",t,[1,4])}chrome.runtime.onMessage.addListener((e,t,r)=>{var a;if(e.action==="PredictForest"&&((a=t.tab)!=null&&a.id))return nr?((async()=>{try{const n=nr.inputNames[0],i=nr.outputNames[1],s=Sg(e.features),d=(await nr.run({[n]:s}))[i].data[1],l=d>=kg;pa[t.tab.id]={probability:d,isPhishing:l},console.log(`🧠 Prediction for tab ${t.tab.id}:`,pa[t.tab.id]),r({probability:d,isPhishing:l})}catch(n){console.error("❌ Prediction error:",n),r({error:n.message})}})(),!0):(r({error:"Model not ready"}),!0);if(e.action==="GetStoredPrediction"&&e.tabId){const n=pa[e.tabId];return console.log(`📤 Returning cached prediction for tab ${e.tabId}:`,n),r(n||{error:"No prediction yet"}),!1}});
