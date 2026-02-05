



// Desktop navigation functionality
document.querySelectorAll("[data-submenu-toggle]").forEach((toggle) => {
  toggle.addEventListener("click", (e) => {
    e.stopPropagation();
    const item = toggle.closest(".nav-item");
    if (!item) return;
    
    const isOpen = item.classList.toggle("is-open");
    toggle.setAttribute("aria-expanded", String(isOpen));
    
    // Close other submenus at the same level
    if (isOpen) {
      const parent = item.parentElement;
      if (parent) {
        parent.querySelectorAll(".nav-item.is-open").forEach((sibling) => {
          if (sibling !== item) {
            sibling.classList.remove("is-open");
            const siblingToggle = sibling.querySelector("[data-submenu-toggle]");
            if (siblingToggle) {
              siblingToggle.setAttribute("aria-expanded", "false");
            }
          }
        });
      }
    }
  });
});

// Mobile bottom navigation
const mobileMenuToggle = document.getElementById("mobile-menu-toggle");
const mobileMenuOverlay = document.getElementById("mobile-menu-overlay");
const mobileMenuClose = document.getElementById("mobile-menu-close");
const mobileMenuContent = document.getElementById("mobile-menu-content");

// Function to render mobile menu from menu_items data
function renderMobileMenu() {
  if (!mobileMenuContent) return;
  
  // Get menu items from global variable or create default menu
  const menuItems = window.menuItems || [
    { title: "Головна", url: "/", children: [] },
    { title: "Про коледж", url: "#", children: [
      { title: "Історія", url: "/history" },
      { title: "Адміністрація", url: "/admin" },
      { title: "Викладачі", url: "/teachers" }
    ]},
    { title: "Новини", url: "/articles", children: [] },
    { title: "Вступ", url: "/admissions-2026", children: [
      { title: "Правила прийому", url: "/admission-rules" },
      { title: "Спеціальності", url: "/specialties" }
    ]},
    { title: "Студентам", url: "#", children: [
      { title: "Розклад", url: "/schedule" },
      { title: "Бібліотека", url: "/library" }
    ]}
  ];
  
  let mobileHTML = '';
  
  menuItems.forEach(item => {
    const hasSubmenu = item.children && item.children.length > 0;
    const isActive = window.activeTitle === item.title;
    
    if (hasSubmenu) {
      mobileHTML += `
        <div class="mobile-nav-group">
          <div class="mobile-nav-group-title">${item.title}</div>
          <div class="mobile-submenu">
      `;
      
      item.children.forEach(child => {
        const childActive = window.activeTitle === child.title;
        mobileHTML += `
          <a href="${child.url}" class="mobile-nav-link ${childActive ? 'active' : ''}">${child.title}</a>
        `;
      });
      
      mobileHTML += `
          </div>
        </div>
      `;
    } else {
      mobileHTML += `
        <a href="${item.url}" class="mobile-nav-link ${isActive ? 'active' : ''}">${item.title}</a>
      `;
    }
  });
  
  mobileMenuContent.innerHTML = mobileHTML;
}

// Mobile menu toggle
if (mobileMenuToggle && mobileMenuOverlay) {
  mobileMenuToggle.addEventListener("click", () => {
    renderMobileMenu();
    mobileMenuOverlay.classList.add("is-open");
    document.body.style.overflow = "hidden";
  });
}

// Close mobile menu
if (mobileMenuClose && mobileMenuOverlay) {
  mobileMenuClose.addEventListener("click", () => {
    mobileMenuOverlay.classList.remove("is-open");
    document.body.style.overflow = "";
  });
}

// Close mobile menu when clicking overlay
if (mobileMenuOverlay) {
  mobileMenuOverlay.addEventListener("click", (e) => {
    if (e.target === mobileMenuOverlay) {
      mobileMenuOverlay.classList.remove("is-open");
      document.body.style.overflow = "";
    }
  });
}

// Handle window resize
window.addEventListener("resize", () => {
  if (window.innerWidth > 960) {
    document.body.style.overflow = "";
    if (mobileMenuOverlay) mobileMenuOverlay.classList.remove("is-open");
  }
});
