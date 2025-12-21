from flask import Flask, request, jsonify
from transformers import pipeline

app = Flask(__name__)

# Load a pre-trained model for text generation (like DialoGPT)
chatbot = pipeline('text-generation', model='microsoft/DialoGPT-medium')

@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message')
    
    # Use the text generation model to generate a response
    response = chatbot(user_message, max_length=150, num_return_sequences=1)

    return jsonify({'response': response[0]['generated_text']})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
