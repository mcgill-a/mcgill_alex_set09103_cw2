// Get modal element
var modal = document.getElementById("userModal");
// Get modal buttons
var modalSignIn = document.getElementById("modalSignIn");
var modalSignUp = document.getElementById("modalSignUp");
var modalCloseBtn = document.getElementsByClassName("closeBtn")[0];

// Modal Event listeners
modalSignIn.addEventListener('click', openModal);
modalSignUp.addEventListener('click', openModal);
/*modalCloseBtn.addEventListener('click', closeModal);*/

window.addEventListener('click', clickOutside);

function openModal()
{
  modal.style.display = "block";
}

function closeModal()
{
  modal.style.display = "none";
}

// Close Modal if outside click
function clickOutside(e)
{
  if(e.target == modal)
  {
    modal.style.display = "none";
  }
  
}

function scrollTo(element) {
  window.scroll({
    top: element.getBoundingClientRect().top + window.scrollY,
    left: 0,
    behavior: 'smooth'
  });
}