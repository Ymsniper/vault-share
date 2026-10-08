// Small additions to the forms. Every page still works without them.
// Served from this site, so the Content-Security-Policy lets it run.

const EYE =
  '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" ' +
  'stroke-width="1.5" aria-hidden="true"><path d="M1 8s2.5-5 7-5 7 5 7 5-2.5 5-7 5-7-5-7-5z"/>' +
  '<circle cx="8" cy="8" r="2.2"/></svg>';
const EYE_SLASH = EYE.replace("</svg>", '<path d="M2 2l12 12"/></svg>');

// An eye button that shows or hides what was typed. A field marked "masked"
// is a text field hidden with CSS (so password managers leave it alone):
// for it the button toggles the class instead of the type.
function addRevealButton(input) {
  const group = document.createElement("div");
  group.className = "input-group";
  input.replaceWith(group);
  group.append(input);

  const button = document.createElement("button");
  button.type = "button";
  button.className = "btn btn-outline-secondary";
  group.append(button);

  const masked = input.classList.contains("masked");
  const isHidden = () => (masked ? input.classList.contains("masked") : input.type === "password");
  const render = () => {
    button.innerHTML = isHidden() ? EYE : EYE_SLASH;
    button.setAttribute("aria-label", isHidden() ? "Show what I typed" : "Hide what I typed");
  };
  button.addEventListener("click", () => {
    if (masked) {
      input.classList.toggle("masked");
    } else {
      input.type = input.type === "password" ? "text" : "password";
    }
    render();
    input.focus();
  });
  render();
}

// A button that clears the chosen file, shown only once a file is chosen.
function addRemoveFileButton(input) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "btn btn-outline-secondary btn-sm mt-2";
  button.textContent = "Remove file";
  input.after(button);

  const render = () => {
    button.hidden = input.files.length === 0;
  };
  button.addEventListener("click", () => {
    input.value = "";
    render();
  });
  input.addEventListener("change", render);
  render();
}

for (const input of document.querySelectorAll('input[type="password"], input.masked')) {
  addRevealButton(input);
}
for (const input of document.querySelectorAll('input[type="file"]')) {
  addRemoveFileButton(input);
}
