//@ts-nocheck

import { usePage } from "@inertiajs/react";
import React from "react";

const Home: React.FC = () => {
    const { user, csrfToken } = usePage().props;

    return (
        <>
            <div className="absolute right-2 top-2">
                {user && (
                    <section className="flex space-x-2">
                        <p className="text-gray-700">{user.email}</p>
                        <form action="/logout" method="POST">
                            <input type="hidden" name="_token" value={csrfToken} />
                            <input type="hidden" name="_method" value="DELETE" />
                            <button type="submit" className="text-indigo-500 text-xs">(Log Out)</button>
                        </form>
                    </section>
                )}
            </div>

            <div className="flex flex-col h-screen justify-center items-center">
                <p>To customize this page, edit this file: <kbd className="text-indigo-600">./resources/js/Pages/Home.tsx</kbd></p>
            </div>
        </>
    );
};

export default Home;
