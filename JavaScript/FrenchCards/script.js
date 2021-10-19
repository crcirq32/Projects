// define the object for the question entity
let question = {
  title: 'gato',
  alternatives: ['dog', 'cat', 'bird', 'fish'],
  correctAnswer: 1
};

// function for showing the question
function showQuestion(q) {
  // show question title
  let titleDiv = document.getElementById('title');
  titleDiv.textContent = q.title;
  
  // show alternatives
  let alts = document.querySelectorAll('.alternative');
  
  alts.forEach(function(element, index){
    element.textContent = q.alternatives[index];
    
    // listening for events
    element.addEventListener('click', function(){
      // check correct answer
      if(q.correctAnswer == index) {
        console.log('Correct Answer!');
      }
      else {
        console.log('Wrong Answer!');
      }
    });
    
  });
}

// call the function
showQuestion(question);

// select the button element
let btn = document.getElementById('btn');

// listening to click events
btn.addEventListener('click', function(){
  console.log('Clicked!');
});
