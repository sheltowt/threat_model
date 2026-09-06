/// <reference types="vite/client" />

declare module '*.yaml?url' {
  const url: string;
  export default url;
}
