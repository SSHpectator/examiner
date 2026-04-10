from gmailExtractor import GMAIL_EXTRACTOR

def main():
    bot = GMAIL_EXTRACTOR()
    bot.sayHello()
    bot.initVars()
    service = bot.getLogin()
    
    if service:
        print("\n[OK] Connessione alle API di Gmail stabilita.")
        # Avvia l'analisi dei PDF
        bot.getPDF(service)
    else:
        print("\n[!] Errore durante la fase di login.")

if __name__ == "__main__":
    main()