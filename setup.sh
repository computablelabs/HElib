echo 'rm -rf build/'
rm -rf build/
echo 'cd src'
cd src
echo 'make clean'
make clean
echo 'make -j4'
make -j4
echo 'rm ${LD_LIBRARY_PATH}/fhe.a'
rm ${LD_LIBRARY_PATH}/fhe.a
echo 'cp fhe.a ${LD_LIBRARY_PATH}'
cp fhe.a ${LD_LIBRARY_PATH} 
echo 'rm -rf ${LD_LIBRARY_PATH}/python3.5/site-packages/hepy*'
rm -rf ${LD_LIBRARY_PATH}/python3.5/site-packages/hepy*
echo 'cd ..'
cd ..
echo 'python setup.py install --force'
python setup.py install --force
