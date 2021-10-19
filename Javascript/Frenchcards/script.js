let questions = [
    {
        title: 'chien',
        alternatives: ['dog', 'cat', 'bird', 'fish'],
        correctAnswer: 0
    },
    {
        title: 'oiseau',
        alternatives: ['hamster', 'mouse', 'lizard', 'bird'],
        correctAnswer: 3
    },
    {
        title: 'tigre',
        alternatives: ['rat', 'fish', 'tiger', 'cat'],
        correctAnswer: 3
    },
        {
        title: 'pingouin',
        alternatives: ['dung beatle', 'penguin', 'rat', 'dog'],
        correctAnswer: 2
    },
        {
        title: 'autruche',
        alternatives: ['whale', 'ostrich', 'dog', 'shark'],
        correctAnswer: 2
    },
        {
        title: 'baleine',
        alternatives: ['alagator', 'fish', 'whale', 'tiger'],
        correctAnswer: 3
    },
        {
        title: 'araignée',
        alternatives: ['mouse', 'spider', 'shark', 'tiger'],
        correctAnswer: 3
    },
    {
        title: 'mouche',
        alternatives: ['fly', 'puma', 'fish', 'dog'],
        correctAnswer: 0
    }
];

let app = {
    start: function() {
        this.currPosition = 0;
        this.score = 0;
        // get alternatives
        let alts = document.querySelectorAll('.alternative');
        alts.forEach((element, index) => {
            element.addEventListener('click', () => {
                // check correct answer
                this.checkAnswer(index);
            });
        });
        // refresh stats
        this.updateStats();
        // show first question
        this.showQuestion(questions[this.currPosition]);
    },
        //Question display function
    showQuestion: function(q) {
        // show question title
        let titleDiv = document.getElementById('title');
        titleDiv.textContent = q.title;
        // show alternatives
        let alts = document.querySelectorAll('.alternative');
        //index alternatives
        alts.forEach(function(element, index){
            element.textContent = q.alternatives[index];
        });
    },
        //function checks correct answer
    checkAnswer: function(userSelected) {
        let currQuestion = questions[this.currPosition];
        if(currQuestion.correctAnswer ==  userSelected) {
            // correct
            console.log('correct');
            this.score++;
            this.showResult(true);
        }
        else {
            // incorrect
            console.log('wrong');
            this.showResult(false);
        }
        // refresh stats
        this.updateStats();
        // increase position
        this.increasePosition();
        // show next question
        this.showQuestion(questions[this.currPosition]);
    },
        //itirate questions
    increasePosition: function() {
        this.currPosition++;
        if(this.currPosition == questions.length) {
            this.currPosition = 0;
        }
    },
        //function for score
    updateStats: function() {
        let scoreDiv = document.getElementById('score');
        scoreDiv.textContent = `Your score: ${this.score}`;
    },
        // function of correct answer
    showResult: function(isCorrect) {
        let resultDiv = document.getElementById('result');
        let result = '';
        // check answer
        if(isCorrect) {
            result = 'Correct Answer!';
        }
        else {
            // get the current question
            let currQuestion = questions[this.currPosition];
            // get correct answer (index)
            let correctAnswIndex = currQuestion.correctAnswer;
            // get correct answer (text)
            let correctAnswText = currQuestion.alternatives[correctAnswIndex];
            result = `Wrong! Correct answer: ${correctAnswText}`;
        }
        resultDiv.textContent = result;
    }
};
app.start();
