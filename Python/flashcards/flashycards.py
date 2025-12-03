import random

class FlashcardApp:
    def __init__(self):
        self.flashcards = {}

    def load_flashcards(self, question_file, answer_file):
        try:
            with open(question_file, 'r') as qf, open(answer_file, 'r') as af:
                questions = qf.readlines()
                answers = af.readlines()

                if len(questions) != len(answers):
                    print("Error: The number of questions and answers must match.")
                    return

                for question, answer in zip(questions, answers):
                    self.flashcards[question.strip()] = answer.strip()
                print(f"Loaded {len(self.flashcards)} flashcards.")
        except FileNotFoundError as e:
            print(f"Error: {e}")

    def review_flashcards(self):
        if not self.flashcards:
            print("No flashcards available. Please load some.")
            return
        
        question = random.choice(list(self.flashcards.keys()))
        print(f"Question: {question} - Answer: {self.flashcards[question]}")

    def quiz(self):
        if not self.flashcards:
            print("No flashcards available. Please load some.")
            return
        
        score = 0
        questions = list(self.flashcards.keys())
        random.shuffle(questions)

        for question in questions:
            answer = input(f"Q: {question} -> ")
            if answer.lower() == self.flashcards[question].lower():
                print("Correct!")
                score += 1
            else:
                print(f"Incorrect! The answer is: {self.flashcards[question]}")
        
        print(f"You scored {score}/{len(questions)}")

    def run(self):
        while True:
            print("\nOptions:")
            print("1. Load flashcards from files")
            print("2. Review a random flashcard")
            print("3. Quiz me")
            print("4. Exit")
            
            choice = input("Choose an option: ")
            if choice == '1':
                question_file = input("Enter the question file name (e.g., question.txt): ")
                answer_file = input("Enter the answer file name (e.g., answer.txt): ")
                self.load_flashcards(question_file, answer_file)
            elif choice == '2':
                self.review_flashcards()
            elif choice == '3':
                self.quiz()
            elif choice == '4':
                print("Exiting the flashcard app.")
                break
            else:
                print("Invalid option. Please try again.")

if __name__ == '__main__':
    app = FlashcardApp()
    app.run()

