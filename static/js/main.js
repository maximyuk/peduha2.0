const navToggle = document.querySelector("[data-nav-toggle]");
const nav = document.querySelector("[data-nav]");

if (navToggle && nav) {
  navToggle.addEventListener("click", () => {
    const isOpen = nav.classList.toggle("is-open");
    navToggle.setAttribute("aria-expanded", String(isOpen));
    if (!isOpen) {
      document.querySelectorAll(".nav-item.is-open").forEach((item) => {
        item.classList.remove("is-open");
      });
      document.querySelectorAll("[data-submenu-toggle]").forEach((toggle) => {
        toggle.setAttribute("aria-expanded", "false");
      });
    }
  });
}

document.querySelectorAll("[data-submenu-toggle]").forEach((toggle) => {
  toggle.addEventListener("click", () => {
    const item = toggle.closest(".nav-item");
    if (!item) return;
    const isOpen = item.classList.toggle("is-open");
    toggle.setAttribute("aria-expanded", String(isOpen));
  });
});
