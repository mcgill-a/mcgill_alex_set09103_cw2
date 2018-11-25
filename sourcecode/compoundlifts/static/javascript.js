
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
  if (tab == "tab-overview-content")
  {
    document.getElementById("tab-overview").classList.remove('active');
    document.getElementById("tab-overview").classList.add('active');
    document.getElementById("tab-program").classList.remove('active');
    document.getElementById("tab-followers").classList.remove('active');
    document.getElementById("tab-following").classList.remove('active');
  }
  else if (tab == "tab-program-content")
  {
    document.getElementById("tab-program").classList.remove('active');
    document.getElementById("tab-program").classList.add('active');
    document.getElementById("tab-overview").classList.remove('active');
    document.getElementById("tab-followers").classList.remove('active');
    document.getElementById("tab-following").classList.remove('active');
  }
  else if (tab == "tab-followers-content")
  {
    document.getElementById("tab-followers").classList.remove('active');
    document.getElementById("tab-followers").classList.add('active');
    document.getElementById("tab-overview").classList.remove('active');
    document.getElementById("tab-program").classList.remove('active');
    document.getElementById("tab-following").classList.remove('active');
  }
  else if (tab == "tab-following-content")
  {
    document.getElementById("tab-following").classList.remove('active');
    document.getElementById("tab-following").classList.add('active');
    document.getElementById("tab-overview").classList.remove('active');
    document.getElementById("tab-program").classList.remove('active');
    document.getElementById("tab-followers").classList.remove('active');
  }
}

function openModal(id)
{
  var current_modal = document.getElementById(id);
  current_modal.style.display = "block";
}

function closeModal(id)
{
  var current_modal = document.getElementById(id);
  current_modal.style.display = "none";
}