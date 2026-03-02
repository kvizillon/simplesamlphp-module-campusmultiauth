const closeMessage = (e) => {
  e.target.parentElement.classList.add("hide");
  e.preventDefault();
  return false;
};

document.addEventListener("DOMContentLoaded", () => {
  // close buttons
  document.querySelectorAll(".message__close").forEach((closeButton) => {
    closeButton.addEventListener("click", closeMessage);
  });

  // allow WebAuthn and OTP on one page
  ["otp", "submitButton"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) {
      el.classList.remove("hidden");
    }
  });

  const piLoginForm = document.getElementById("piLoginForm");
  if (piLoginForm) {
    piLoginForm.addEventListener("submit", () => {
      document.getElementById("mode").value = "otp";
    });
  }
});
