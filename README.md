# TD_ransomwarQ1 : Quelle est le nom de l'algorithme de chiffrement ? Est-il robuste et pourquoi ?

L'algorithme de chiffrement utilisé est (XOR). Est une technique de cryptage simple qui repose sur l'utilisation de l'opérateur XOR pour combiner les données à chiffrer avec une clé secrète.

Les raisons pour lesquelles l'algorithme XOR n'est pas considéré comme robuste sont :

- La faiblesse de la clé : si la clé utilisée est facile à deviner, le chiffrement peut être facilement déchiffré.
- L'analyse de fréquence : le chiffrement XOR ne cache pas la distribution des bits dans les données chiffrées, ce qui peut aider les attaquants à déterminer la nature des données chiffrées.
- La vulnérabilité à la répétition : l'utilisation répétée de la même clé XOR peut exposer les données chiffrées à des attaques de répétition, où un attaquant peut observer les données chiffrées à plusieurs reprises pour identifier des modèles.

Pour ces raisons, l'algorithme XOR n'est pas recommandé pour les applications de sécurité avancées, et d'autres algorithmes de chiffrement plus robustes.

Q2 : Pourquoi ne pas hacher le sel et la clef directement ? Et avec un hmac ?

Il n'est pas recommandé de hacher directement la clé et le sel pour plusieurs raisons: 
1.Les fonctions de hachage ne sont pas conçues pour le chiffrement ou la protection de l'intégrité des données.
2.Un hachage ne fournit pas d'authentification de message.
3.Utiliser une fonction de hachage pour dériver une clé de chiffrement est considéré comme une pratique de sécurité faible.
4.Il est recommandé d'utiliser une fonction spécialement conçue pour cela, comme PBKDF2 ou Scrypt, pour dériver la clé de chiffrement.

Et avec un hmac ?

L'utilisation d'un HMAC est une méthode plus sûre pour dériver une clé de chiffrement car il utilise une clé secrète pour générer un code d'authentification de message qui peut garantir l'intégrité des données chiffrées. Cependant, il est préférable d'utiliser une fonction de dérivation de clé telle que PBKDF2 ou Scrypt pour générer la clé à partir du mot de passe et du sel, plutôt que de simplement hacher la clé et le sel ensemble, pour une sécurité renforcée.

Q3 : Pourquoi il est préférable de vérifier qu'un fichier token.bin n'est pas déjà présent ?

Il est préférable de vérifier qu'un fichier token.bin n'est pas déjà présent pour éviter de perdre des données précédentes ou de causer des erreurs dans l'application, il est recommandé de vérifier si un fichier token.bin existe déjà avant d'en créer une nouvelle version. L'application peut alors décider de renommer, copier ailleurs ou écraser le fichier existant si nécessaire, tout en évitant la perte de données. En somme, une vérification préalable permet d'éviter des conséquences fâcheuses et d'assurer le bon fonctionnement de l'application. En plus, pour éviter de générer,d'envoyer et de consommer des éléments cryptographiques inutiles.

Q4 : Comment vérifier que la clef la bonne ?

D'abord la clé fournie doit être décodée à partir du format base64 en utilisant la méthode decode() de la classe bytes.
Ensuite, la clé doit être utilisée pour déchiffrer le fichier token.bin stocké localement avec l'algorithme de chiffrement utilisé initialement et le sel correspondant.
Si le résultat correspond au token stocké, la clé est valide pour déchiffrer les fichiers. Sinon, une exception doit être levée pour informer que la clé est invalide.
