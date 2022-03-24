# SWI - Rapport - Laboratoire 1

## Deauthentication attack

**Question** : quel code est utilisé par aircrack pour déauthentifier un client 802.11. Quelle est son interpretation ?

```
Le code utilisé par aircrack pour déauthentifier est le "-0". Ce code représente le "deauthentication attack mode".
```

**Question** : A l'aide d'un filtre d'affichage, essayer de trouver d'autres trames de déauthentification dans votre capture. Avez-vous en trouvé d'autres ? Si oui, quel code contient-elle et quelle est son interpretation ?

```
Code 03 : station is leaving (or has left) IBSS or ESS
Code 07 : Class 3 frame received from nonassociated station
Code : 
Code : 
```

image1

image2

b) Développer un script en Python/Scapy capable de générer et envoyer des trames de déauthentification. Le script donne le choix entre des Reason codes différents (liste ci-après) et doit pouvoir déduire si le message doit être envoyé à la STA ou à l'AP :

- 1 - Unspecified
- 4 - Disassociated due to inactivity
- 5 - Disassociated because AP is unable to handle all currently associated stations
- 8 - Deauthenticated because sending STA is leaving BSS

**Question** : quels codes/raisons justifient l'envoie de la trame à la STA cible et pourquoi ?

```
1 et 4 et 5
```

**Question** : quels codes/raisons justifient l'envoie de la trame à l'AP et pourquoi ?

```
8
```

**Question** : Comment essayer de déauthentifier toutes les STA ?

```
En précisant l'adresse de broadcast comme target (ff:ff:ff:ff:ff:ff)
```

**Question** : Quelle est la différence entre le code 3 et le code 8 de la liste ?

```
Code 8 est pour BSS
Code 3 est pour IBSS et ESS
```

**Question** : Expliquer l'effet de cette attaque sur la cible

```
La cible se retrouve déconnectée du réseau sans fil
```



## Probe Request Evil Twin Attack

**Question** : comment ça se fait que ces trames puissent être lues par tout le monde ? Ne serait-il pas plus judicieux de les chiffrer ?

```
Ces trames doivent pouvoir être accessible par tout le monde puisque c'est le système utilisé pour détecter les Wi-Fi aux alentours.
```

**Question** : pourquoi les dispositifs iOS et Android récents ne peuvent-ils plus être tracés avec cette méthode ?

```
Parce que le MAC est désormais randomisé à chaque connection
```
