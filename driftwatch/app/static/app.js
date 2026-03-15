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
