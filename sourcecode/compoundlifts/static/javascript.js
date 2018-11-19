// Get modal element
var modal = document.getElementById("userModal");
// Get modal buttons
var modalSignIn = document.getElementById("modalSignIn");
var modalSignUp = document.getElementById("modalSignUp");
var modalCloseBtn = document.getElementsByClassName("closeBtn")[0];

//window.addEventListener('click', clickOutside);

function openModal(tab)
{
  openTab(tab);
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
/*
function clickOutside(e)
{
  if(e.target == modal)
  {
    modal.style.display = "none";
  }
}
*/

// Open the selected modal tab
function openTab(tab)
{
  var tabs = document.getElementsByClassName("tab-content");
  for (var i = 0; i < tabs.length; i++)
  {
    // Hide content from all tabs
    tabs[i].style.display = "none";
  }
  // Display the selected tab content
  document.getElementById(tab).style.display = "flex";

  // Set the correct active tab
  if (tab == "tab-overview")
  {
    document.getElementById("btn-overview").classList.remove('active');
    document.getElementById("btn-overview").classList.add('active');
    document.getElementById("btn-followers").classList.remove('active');
    document.getElementById("btn-following").classList.remove('active');
  }
  else if (tab == "tab-followers")
  {
    document.getElementById("btn-followers").classList.remove('active');
    document.getElementById("btn-followers").classList.add('active');
    document.getElementById("btn-overview").classList.remove('active');
    document.getElementById("btn-following").classList.remove('active');
  }
  else if (tab == "tab-following")
  {
    document.getElementById("btn-following").classList.remove('active');
    document.getElementById("btn-following").classList.add('active');
    document.getElementById("btn-overview").classList.remove('active');
    document.getElementById("btn-followers").classList.remove('active');
  }
}


function scrollTo(element) {
  window.scroll({
    top: element.getBoundingClientRect().top + window.scrollY,
    left: 0,
    behavior: 'smooth'
  });
}