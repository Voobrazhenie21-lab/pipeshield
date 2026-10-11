// Intentionally vulnerable client-side bundle for PipeShield v1.1 JS Recon demonstration
const INTERNAL_ORIGIN = "http://10.0.20.51:8080/status";
const ADMIN_EXPORT_ENDPOINT = "/api/v1/admin/users/export";

function renderUserBanner(untrustedHtml) {
  document.getElementById("banner").innerHTML = untrustedHtml;
  window.parent.postMessage({ status: "loaded" }, "*");
}

//# sourceMappingURL=frontend_bundle.js.map
