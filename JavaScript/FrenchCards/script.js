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
        title: 'chat',
        alternatives: ['rat', 'fish', 'shark', 'cat'],
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

    showQuestion: function(q) {

        // show question title
        let titleDiv = document.getElementById('title');
        titleDiv.textContent = q.title;

        // show alternatives
        let alts = document.querySelectorAll('.alternative');

        alts.forEach(function(element, index){
            element.textContent = q.alternatives[index];
        });
    },

    checkAnswer: function(userSelected) {

        let currQuestion = questions[this.currPosition];

        if(currQuestion.correctAnswer ==  userSelected) {
            // correct
            console.log('correct');
            this.score++;
            this.showResult(true);
        }
        else {
            // not correct
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

    increasePosition: function() {
        this.currPosition++;

        if(this.currPosition == questions.length) {
            this.currPosition = 0;
        }
    },

    updateStats: function() {
        let scoreDiv = document.getElementById('score');
        scoreDiv.textContent = `Your score: ${this.score}`;
    },

    showResult: function(isCorrect) {
        let resultDiv = document.getElementById('result');
        let result = '';

        // checks
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
