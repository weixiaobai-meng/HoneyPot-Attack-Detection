console.log("systemwire local parasitic test script loaded");
document.addEventListener("DOMContentLoaded", () => {
  const marker = document.createElement("meta");
  marker.name = "systemwire-local-test";
  marker.content = "parasitic-script-loaded";
  document.head.appendChild(marker);
});
