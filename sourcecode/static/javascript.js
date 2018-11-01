// Get modal element
var modal = document.getElementById("userModal");
// Get modal buttons
var modalSignIn = document.getElementById("modalSignIn");
var modalSignUp = document.getElementById("modalSignUp");
var modalCloseBtn = document.getElementsByClassName("closeBtn")[0];

window.addEventListener('click', clickOutside);

function openModal(tab)
{
  openModalTab(tab);
  modal.style.display = "block";
}

/*
modalCloseBtn.addEventListener('click', closeModal);

function closeModal()
{
  modal.style.display = "none";
}
*/

// Close Modal if outside click
function clickOutside(e)
{
  if(e.target == modal)
  {
    modal.style.display = "none";
  }
}

// Open the selected modal tab
function openModalTab(tab)
{
  var tabs = document.getElementsByClassName("modal-tab-content");
  for (var i = 0; i < tabs.length; i++)
  {
    // Hide content from all tabs
    tabs[i].style.display = "none";
  }
  // Display the selected tab content
  document.getElementById(tab).style.display = "flex";

  // Set the correct active tab
  if (tab == "sign-in-content")
  {
    document.getElementById("sign-in-tab").classList.remove('active');
    document.getElementById("sign-in-tab").classList.add('active');
    document.getElementById("sign-up-tab").classList.remove('active');
  }
  else
  {
    document.getElementById("sign-up-tab").classList.remove('active');
    document.getElementById("sign-up-tab").classList.add('active');
    document.getElementById("sign-in-tab").classList.remove('active');
  }
}

function scrollTo(element) {
  window.scroll({
    top: element.getBoundingClientRect().top + window.scrollY,
    left: 0,
    behavior: 'smooth'
  });
}