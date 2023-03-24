{
 "cells": [
  {
   "cell_type": "code",
   "execution_count": 1,
   "id": "23c7df86",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Mirza\n"
     ]
    }
   ],
   "source": [
    "print(\"Mirza\")"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 2,
   "id": "55085ebe",
   "metadata": {},
   "outputs": [],
   "source": [
    "# "
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 3,
   "id": "4dad3feb",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Shift+Enter  - It will run and it will next line\n",
    "# ctrl +enter - just run"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 4,
   "id": "c3ceffb7",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Variable  - Temporary Storage "
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 5,
   "id": "97298df2",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Variable_name = value \n",
    "jay=10  # we store a number"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 6,
   "id": "92cb9af0",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "jay\n"
     ]
    }
   ],
   "source": [
    "print(\"jay\")"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 7,
   "id": "ba5ff6b2",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "10\n"
     ]
    }
   ],
   "source": [
    "print(jay)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 8,
   "id": "52a79daf",
   "metadata": {},
   "outputs": [
    {
     "ename": "NameError",
     "evalue": "name 'Jay' is not defined",
     "output_type": "error",
     "traceback": [
      "\u001b[1;31m---------------------------------------------------------------------------\u001b[0m",
      "\u001b[1;31mNameError\u001b[0m                                 Traceback (most recent call last)",
      "Input \u001b[1;32mIn [8]\u001b[0m, in \u001b[0;36m<cell line: 1>\u001b[1;34m()\u001b[0m\n\u001b[1;32m----> 1\u001b[0m \u001b[38;5;28mprint\u001b[39m(\u001b[43mJay\u001b[49m)\n",
      "\u001b[1;31mNameError\u001b[0m: name 'Jay' is not defined"
     ]
    }
   ],
   "source": [
    "print(Jay)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 9,
   "id": "0856e2fa",
   "metadata": {},
   "outputs": [],
   "source": [
    "var123 = \"Merra\"  # We can store character "
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 10,
   "id": "9e4bef9e",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Merra\n"
     ]
    }
   ],
   "source": [
    "print(var123)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 11,
   "id": "f6a76511",
   "metadata": {},
   "outputs": [
    {
     "ename": "SyntaxError",
     "evalue": "invalid syntax (3414805172.py, line 1)",
     "output_type": "error",
     "traceback": [
      "\u001b[1;36m  Input \u001b[1;32mIn [11]\u001b[1;36m\u001b[0m\n\u001b[1;33m    123var=\"Joy\"\u001b[0m\n\u001b[1;37m       ^\u001b[0m\n\u001b[1;31mSyntaxError\u001b[0m\u001b[1;31m:\u001b[0m invalid syntax\n"
     ]
    }
   ],
   "source": [
    "123var=\"Joy\" # start with numbers in variale declaration , is not possible "
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 12,
   "id": "877ac3b7",
   "metadata": {},
   "outputs": [],
   "source": [
    "v_1=10"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 13,
   "id": "12737af4",
   "metadata": {},
   "outputs": [],
   "source": [
    "_v=20"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 14,
   "id": "f28311e7",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "10\n",
      "20\n",
      "30\n"
     ]
    }
   ],
   "source": [
    "v1=10\n",
    "v2=20\n",
    "v3=30\n",
    "print(v1)\n",
    "print(v2)\n",
    "print(v3)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 16,
   "id": "87deb48d",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "10 20 30\n",
      "v1,v2,v3\n"
     ]
    }
   ],
   "source": [
    "v1,v2,v3 = 10,20,30\n",
    "print(v1,v2,v3)\n",
    "print(\"v1,v2,v3\")"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 21,
   "id": "99a268f7",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "10 Python 20.45\n"
     ]
    }
   ],
   "source": [
    "v1,v2,v3 = 10,\"Python\",20.45\n",
    "print(v1,v2,v3)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 18,
   "id": "5d346298",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Global - Global variable "
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 19,
   "id": "d323c22d",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "10\n"
     ]
    }
   ],
   "source": [
    "print(jay)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 20,
   "id": "e663efd9",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "10 20 30\n",
      "v1,v2,v3\n"
     ]
    }
   ],
   "source": [
    "v1,v2,v3 = 10,20,30\n",
    "print(v1,v2,v3)\n",
    "print(\"v1,v2,v3\")"
   ]
  },
  {
   "cell_type": "markdown",
   "id": "6747bee9",
   "metadata": {},
   "source": [
    "# Operator"
   ]
  },
  {
   "cell_type": "markdown",
   "id": "a3cbd363",
   "metadata": {},
   "source": [
    "# Arithmatic"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 22,
   "id": "91bec87c",
   "metadata": {},
   "outputs": [
    {
     "data": {
      "text/plain": [
       "40"
      ]
     },
     "execution_count": 22,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "20+20"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 23,
   "id": "705fe97c",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "40\n"
     ]
    }
   ],
   "source": [
    "print(20+20)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 2,
   "id": "4af5093b",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "<class 'int'>\n",
      "Enter the value:12\n",
      "30\n",
      "12\n",
      "-10\n",
      "200\n",
      "0.5\n",
      "9\n",
      "2\n",
      "6\n"
     ]
    }
   ],
   "source": [
    "V1=10 # static value \n",
    "V2=20 \n",
    "V3= 3\n",
    "print(type(V1))\n",
    "\n",
    "Var1 = input(\"Enter the value:\")  # Syntax - (Dynamic  value )\n",
    "print(V1+V2) #Addition\n",
    "print(Var1)\n",
    "print(V1-V2) #Subtraction\n",
    "print(V1*V2)\n",
    "print(V1/V2)\n",
    "print(V3 ** 2)\n",
    "print(V2%V3)\n",
    "print(V2//V3)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 30,
   "id": "2203c41d",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Comparison Operators"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 36,
   "id": "42d2d535",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "False\n",
      "True\n",
      "False\n",
      "True\n",
      "True\n",
      "True\n"
     ]
    }
   ],
   "source": [
    "x=10\n",
    "y=20\n",
    "z=10\n",
    "\n",
    "print(x==y)  # Equal \n",
    "print(x!=y) # Not Equal\n",
    "print(x>y)  # Greater than\n",
    "print(x>=z) # Greater than Equal to\n",
    "print(x<y)  # Less than \n",
    "print(x<=z)  # Lesser than Equal to"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 37,
   "id": "e074b174",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Assignment Operator"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 47,
   "id": "5140402b",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "30\n",
      "50\n",
      "30\n",
      "600\n",
      "60.0\n",
      "0.0\n",
      "0.0\n",
      "15\n"
     ]
    }
   ],
   "source": [
    "x=30\n",
    "print(x)\n",
    "x+=20   # x=x+20\n",
    "print(x)\n",
    "x-=20   # x=x-20\n",
    "print(x)\n",
    "x*=20  #x=x*20\n",
    "print(x)\n",
    "x/=10  # x=x/10\n",
    "print(x)\n",
    "x%=10   # x=x%10\n",
    "print(x)\n",
    "x**=2  # x=x** 2\n",
    "print(x)\n",
    "x=30  # intiazation x=30\n",
    "x//=2\n",
    "print(x) # x=x//2"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 48,
   "id": "39b31706",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Logical Operators"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 50,
   "id": "8caa6c28",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "True\n",
      "True\n",
      "False\n"
     ]
    }
   ],
   "source": [
    "x=10\n",
    "y=20 \n",
    "print(x>=10 and x==10) # and\n",
    "print(x<=30 or x<y)  # or \n",
    "print(not(x>=10))  # not "
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 51,
   "id": "afae613e",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Bitwise AND "
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 52,
   "id": "21ea7fd5",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "0\n"
     ]
    }
   ],
   "source": [
    "v1=20\n",
    "v2=10\n",
    "print(v1 & v2)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 53,
   "id": "0f0900b6",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "4\n"
     ]
    }
   ],
   "source": [
    "v1=20\n",
    "v2=4\n",
    "print(v1 & v2)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 54,
   "id": "74e62a78",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "4\n"
     ]
    }
   ],
   "source": [
    "v1=30\n",
    "v2=5\n",
    "print(v1 & v2)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "id": "c16e7bf8",
   "metadata": {},
   "outputs": [],
   "source": []
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3 (ipykernel)",
   "language": "python",
   "name": "python3"
  },
  "language_info": {
   "codemirror_mode": {
    "name": "ipython",
    "version": 3
   },
   "file_extension": ".py",
   "mimetype": "text/x-python",
   "name": "python",
   "nbconvert_exporter": "python",
   "pygments_lexer": "ipython3",
   "version": "3.9.12"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 5
}
