#!/bin/bash
./digi-disasm extract/DIGIMON/SCN/DG.SCN dg
./digi-disasm extract/DIGIMON/SCN/MAPHEAD.SCN maphead.dgs
rm -rf ../scn/DG.SCN
rm -rf ../scn/MAPHEAD.dgs
mv dg ../scn/DG.SCN
mv maphead.dgs ../scn/MAPHEAD.dgs
cp functions.dgs ../scn/
cp entities.dgs ../scn/
