var theSelect = document.querySelector('#sel-opt');
var wrapper = document.createElement('div');
wrapper.classList.add('custom-select-wrapper');
var customSelect = document.createElement('div');
customSelect.classList.add('custom-select');
var customSelectTrigger = document.createElement('div');
customSelectTrigger.classList.add('custom-select__trigger');
var spanText = document.createElement('span');
spanText.textContent = 'Sort By';
var arrow = document.createElement('div');
arrow.classList.add('arrow');
customSelectTrigger.append(spanText, arrow);
customSelect.append(customSelectTrigger);
var customOptions = document.createElement('div');
customOptions.classList.add('custom-options');
var selectOptions = document.querySelectorAll('option');
for(var opt = 0; opt < selectOptions.length; opt++){
  var optSpan = document.createElement('span');
  optSpan.classList.add('custom-option');
  if(!opt){
    optSpan.classList.add('selected', 'hidden');
  }
  var thisVal = selectOptions[opt].value;
  var thisText = selectOptions[opt].textContent;
  optSpan.textContent = thisText;
  optSpan.setAttribute('data_value', thisVal);
  customOptions.append(optSpan);
}
customSelect.append(customOptions);
wrapper.append(customSelect);
var par = theSelect.parentNode;
par.append(wrapper);

document.querySelector('.custom-select-wrapper').addEventListener('click', function() {
    this.querySelector('.custom-select').classList.toggle('open');
})
var option = document.querySelectorAll(".custom-option");
for (var i = 0; i < option.length; i++) {
    option[i].addEventListener('click', function() {
            this.parentNode.querySelector('.custom-option.selected').classList.remove('selected');
            this.classList.add('selected');
            this.closest('.custom-select').querySelector('.custom-select__trigger span').textContent = this.textContent;
    });
}
window.addEventListener('click', function(e) {
    var select = document.querySelector('.custom-select');
    if (!select.contains(e.target)) {
        select.classList.remove('open');
    }
});

 document.querySelector(".custom-select-wrapper").addEventListener('click', function(){
  var choosenOption = document.querySelector(".selected").getAttribute('data-value');
   var optionsSel = document.querySelectorAll('option');
   for(var j = 0; j < optionsSel.length; j++){
     if(optionsSel[j].value == choosenOption){
       optionsSel[j].selected = true;
       // alert(optionsSel[j].value);
     }
   }
 });

