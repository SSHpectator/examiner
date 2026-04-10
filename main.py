from gmailExtractor import GMAIL_EXTRACTOR

def main():
    bot = GMAIL_EXTRACTOR()
    bot.sayHello()
    bot.initVars()
    service = bot.getLogin()
    
    if service:
        print("\n[OK] Estabilished connection to GMAIL's API.")
        # Avvia l'analisi dei PDF
        bot.getPDF(service)
    else:
        print("\n[!] Error during the login phase.")

if __name__ == "__main__":
    main()
