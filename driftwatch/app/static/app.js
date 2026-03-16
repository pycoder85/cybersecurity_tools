document.addEventListener("click", async (event) => {
  const button = event.target.closest(".explain-button");
  if (!button) {
    return;
  }
  const findingId = button.dataset.findingId;
  const output = document.getElementById(`explanation-${findingId}`);
  output.textContent = "Generating deterministic explanation...";
  try {
    const response = await fetch(`/api/findings/${findingId}/explain`, { method: "POST" });
    const payload = await response.json();
    output.textContent = payload.explanation || payload.error || "No explanation available.";
  } catch (error) {
    output.textContent = "Explanation request failed.";
  }
});

document.addEventListener("click", async (event) => {
  const button = event.target.closest(".enrich-button");
  if (!button) {
    return;
  }
  const findingId = button.dataset.findingId;
  const output = document.getElementById(`enrichment-${findingId}`);
  output.textContent = "Running external validation...";
  try {
    const response = await fetch(`/api/findings/${findingId}/enrich`, { method: "POST" });
    const payload = await response.json();
    const matches = (payload.results || []).filter((item) => item.status === "match").length;
    const checked = (payload.observables || []).length;
    output.textContent = payload.message || `Checked ${checked} observable(s); ${matches} produced provider matches.`;
  } catch (error) {
    output.textContent = "External validation request failed.";
  }
});

document.addEventListener("click", async (event) => {
  const button = event.target.closest(".software-enrich-button");
  if (!button) {
    return;
  }
  const recordHash = button.dataset.recordHash;
  const output = document.getElementById(`software-enrichment-${recordHash}`);
  output.textContent = "Running software validation...";
  try {
    const body = new URLSearchParams({ record_hash: recordHash });
    const response = await fetch("/api/software/enrich", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
      body,
    });
    const payload = await response.json();
    output.textContent = payload.message || payload.error || "No validation result available.";
  } catch (error) {
    output.textContent = "Software validation request failed.";
  }
});
