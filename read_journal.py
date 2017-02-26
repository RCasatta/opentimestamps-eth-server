from otsserver.calendar import Journal

journal = Journal( '/Users/casatta/.otsd/eth-calendar/journal')

for idx in range(0, 1000):
    try:
        commitment = journal[idx]
        print(str(idx) + ":" + str(len(commitment)))
        print(commitment)
    except KeyError:
        break


print (idx)
