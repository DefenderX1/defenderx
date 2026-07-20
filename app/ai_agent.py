import json
import threading
import os

try:
    from huggingface_hub import InferenceClient
    HF_HUB_AVAILABLE = True
except ImportError:
    InferenceClient = None
    HF_HUB_AVAILABLE = False

class AIAgent:
    """
    AI Security Agent (DefenderX) that monitors alerts, runs them
    through the Hugging Face InferenceClient, and powers the chatbot.
    """

    def __init__(self, alert_manager, web_dir=None, deploy_dir=None):
        self.alert_manager = alert_manager
        self.web_dir = web_dir
        self.deploy_dir = deploy_dir
        
        
        self.token = self._load_token()
        self.model_name = "google/gemma-3-1b-it"
        
        
        self.client = None
        if HF_HUB_AVAILABLE and self.token:
            try:
                self.client = InferenceClient(
                    provider="featherless-ai",
                    api_key=self.token,
                )
            except Exception:
                pass

    def _load_token(self):
        """Loads Hugging Face token dynamically from env or local text file."""
        token = os.environ.get("HF_TOKEN")
        if not token:
            for path in [
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "hf_token.txt"),
                os.path.join(os.getcwd(), "hf_token.txt"),
                "hf_token.txt"
            ]:
                if os.path.exists(path):
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            t = f.read().strip()
                            if t:
                                return t
                    except Exception:
                        pass
        return token

    def analyze_alert_async(self, alert):
        """Analyze a new alert asynchronously using Hugging Face."""
        if 'ai_analysis' in alert:
            return  # Already analyzed
        threading.Thread(target=self._analyze_alert, args=(alert,), daemon=True).start()

    def _analyze_alert(self, alert):
        if not HF_HUB_AVAILABLE:
            alert['ai_analysis'] = "Error: huggingface_hub package is not installed in the current Python environment. Please run: pip install huggingface-hub"
            self.update_web_alerts(alert)
            return

        
        if not self.token:
            self.token = self._load_token()
            
        if self.token and not self.client:
            try:
                self.client = InferenceClient(
                    provider="featherless-ai",
                    api_key=self.token,
                )
            except Exception as e:
                alert['ai_analysis'] = f"Failed to initialize InferenceClient: {e}"
                self.update_web_alerts(alert)
                return

        if not self.token or not self.client:
            alert['ai_analysis'] = "Hugging Face API Token (HF_TOKEN) is not set."
            self.update_web_alerts(alert)
            return

        messages = [
            {
                "role": "system",
                "content": "You are DefenderX, acting as a Cyber security Organization preventer. Keep all analysis clear, professional, concise (maximum 150 words), and do NOT use emojis."
            },
            {
                "role": "user",
                "content": f"Analyze the following security alert:\nSource: {alert['source']}\nSeverity: {alert['severity']}\nMessage: {alert['message']}\nDetails: {alert['details']}"
            }
        ]

        try:
            # Use chat_completion for the instruction-tuned chat model
            response = self.client.chat_completion(
                messages=messages,
                model=self.model_name,
                max_tokens=250
            )
            
            analysis = response.choices[0].message.content
            alert['ai_analysis'] = analysis.strip()
            self.update_web_alerts(alert)
                
        except Exception as e:
            alert['ai_analysis'] = f"Hugging Face chat completion failed: {str(e)}"
            self.update_web_alerts(alert)

    def generate_chat_reply(self, message_history, callback):
        """Generates a chat response asynchronously for the desktop chatbot."""
        def run():
            if not HF_HUB_AVAILABLE:
                callback("Error: huggingface_hub package is not installed in the current Python environment. Please run: pip install huggingface-hub")
                return

            if not self.token:
                self.token = self._load_token()
                
            if self.token and not self.client:
                try:
                    self.client = InferenceClient(
                        provider="featherless-ai",
                        api_key=self.token,
                    )
                except Exception as e:
                    callback(f"Failed to initialize InferenceClient: {e}")
                    return

            if not self.token or not self.client:
                callback("Hugging Face API Token (HF_TOKEN) is not set.")
                return

            # Construct messages array for chat completion
            messages = [
                {
                    "role": "system",
                    "content": "You are DefenderX, acting as a Cyber security Organization preventer. Assist the user with security questions. Keep responses clear, professional, concise, and do NOT use emojis."
                }
            ] + message_history

            try:
                response = self.client.chat_completion(
                    messages=messages,
                    model=self.model_name,
                    max_tokens=200
                )
                reply = response.choices[0].message.content
                callback(reply.strip())
            except Exception as e:
                callback(f"Hugging Face chat completions failed: {str(e)}")

        threading.Thread(target=run, daemon=True).start()

    def update_web_alerts(self, alert):
        """Update alerts.json in both web and deploy folders."""
        for base_dir in [self.web_dir, self.deploy_dir]:
            if not base_dir or not os.path.exists(base_dir):
                continue
            
            alerts_path = os.path.join(base_dir, "alerts.json")
            alerts_list = []

            if os.path.exists(alerts_path):
                try:
                    with open(alerts_path, 'r', encoding='utf-8') as f:
                        alerts_list = json.load(f)
                except Exception:
                    pass

            # Update existing alert or insert new one
            exists = False
            for idx, a in enumerate(alerts_list):
                if a['id'] == alert['id']:
                    alerts_list[idx] = alert
                    exists = True
                    break

            if not exists:
                alerts_list.insert(0, alert)

            # Keep size reasonable (max 100 alerts)
            alerts_list = alerts_list[:100]

            try:
                with open(alerts_path, 'w', encoding='utf-8') as f:
                    json.dump(alerts_list, f, indent=2)
            except Exception as e:
                print(f"[AIAgent] Error saving web alerts: {e}")
